"""Index verification: structural integrity, payload digests, revisit links."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

from .errors import (
    DigestMismatchError,
    RevisitError,
    TruncatedRecordError,
    WarcError,
    WarcIOError,
)
from .index import WarcIndex
from .models import (
    IDENTICAL_PAYLOAD_PROFILES,
    SERVER_NOT_MODIFIED_PROFILES,
    RecordView,
)
from .reader import materialize, stream_hash_payload

ERROR = "error"
WARNING = "warning"


@dataclass(frozen=True)
class ValidationIssue:
    severity: str  # "error" or "warning"
    code: str
    record_id: str | None
    message: str

    def __str__(self) -> str:
        rid = self.record_id or "-"
        return f"[{self.severity.upper():7}] {self.code} {rid}: {self.message}"


@dataclass
class ValidationReport:
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == ERROR]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == WARNING]

    @property
    def ok(self) -> bool:
        return not self.errors

    def __bool__(self) -> bool:
        return self.ok

    def __iter__(self) -> Iterator[ValidationIssue]:
        return iter(self.issues)

    def __len__(self) -> int:
        return len(self.issues)


def validate_index(
    index: WarcIndex,
    *,
    check_digests: bool = True,
    resolve_revisits: bool = True,
    raise_on_error: bool = False,
) -> ValidationReport:
    """Validate every record in *index*, streaming (never bulk-loading).

    Checks performed:

    * source files still exist and have the recorded size;
    * every stored offset/length parses back into the expected record
      (structural integrity);
    * payload digests recompute to the declared/stored value;
    * truncated records are surfaced as warnings;
    * stored parse warnings are surfaced as warnings;
    * revisit records resolve to a present, untruncated target whose payload
      digest matches.

    With *raise_on_error*, the first error-level issue is raised instead of
    being collected.
    """
    report = ValidationReport()

    def add(severity: str, code: str, rid: str | None, message: str) -> None:
        issue = ValidationIssue(severity, code, rid, message)
        report.issues.append(issue)
        if raise_on_error and severity == ERROR:
            raise _issue_to_error(issue)

    for view in index.query():
        # 1. file availability / size
        try:
            index._ensure_file_ready(view)
        except WarcError as exc:
            add(ERROR, "source-unavailable", view.record_id, str(exc))
            continue

        # 2. stored warnings & truncation
        for warning in view.warnings:
            add(WARNING, "parse-warning", view.record_id, warning)
        if view.truncated:
            add(
                WARNING,
                "truncated",
                view.record_id,
                f"record is truncated: {view.trunc_reason or 'unknown'}",
            )

        # 3. structural + digest check on the bytes actually on disk.
        # Revisit records carry no payload themselves; their digest is
        # verified against the target record in step 4.
        if (
            check_digests
            and not view.truncated
            and view.record_type != "revisit"
        ):
            try:
                _verify_structure_and_digest(index, view, add)
            except WarcError as exc:
                add(ERROR, "structure", view.record_id, str(exc))
            except OSError as exc:
                add(ERROR, "io", view.record_id, str(exc))

        # 4. revisit link validity
        if resolve_revisits and view.record_type == "revisit":
            _verify_revisit(index, view, add)

    return report


def _verify_structure_and_digest(index: WarcIndex, view: RecordView, add) -> None:
    resolved = materialize(
        view.file_path, view.offset, view.length, expected_id=view.record_id
    )
    try:
        if view.payload_digest_algorithm and view.payload_digest:
            actual = stream_hash_payload(
                resolved, view.payload_digest_algorithm
            )
            if actual != view.payload_digest:
                add(
                    ERROR,
                    "digest-mismatch",
                    view.record_id,
                    f"expected {view.payload_digest_algorithm}:"
                    f"{view.payload_digest}, computed {actual}",
                )
    finally:
        resolved.close()


def _verify_revisit(index: WarcIndex, view: RecordView, add) -> None:
    profile = (view.revisit_profile or "").strip()
    if profile in IDENTICAL_PAYLOAD_PROFILES:
        target = index._find_identical_payload_target(view)
    elif profile in SERVER_NOT_MODIFIED_PROFILES:
        target = index._find_server_not_modified_target(view)
    else:
        add(
            ERROR,
            "revisit-profile",
            view.record_id,
            f"unsupported revisit profile: {profile or '(missing)'}",
        )
        return

    if target is None:
        add(
            ERROR,
            "revisit-target-missing",
            view.record_id,
            f"target {view.refers_to or '(by digest/uri)'} not found in index",
        )
        return
    if target.truncated:
        add(
            ERROR,
            "revisit-target-truncated",
            view.record_id,
            f"target {target.record_id} is truncated ({target.trunc_reason})",
        )
        return

    if view.payload_digest and target.payload_digest:
        if view.payload_digest != target.payload_digest:
            add(
                ERROR,
                "revisit-digest-mismatch",
                view.record_id,
                f"revisit digest {view.payload_digest} differs from target "
                f"{target.record_id} digest {target.payload_digest}",
            )
            return
    elif not (
        profile in SERVER_NOT_MODIFIED_PROFILES and view.refers_to
    ):
        add(
            ERROR,
            "revisit-digest-missing",
            view.record_id,
            "neither revisit nor target carries a payload digest; "
            "provenance cannot be verified",
        )
        return

    # Full end-to-end proof: actually resolve and hash the target body.
    try:
        index.resolve(view).close()
    except RevisitError as exc:
        add(ERROR, "revisit-resolve", view.record_id, str(exc))
    except TruncatedRecordError as exc:
        add(ERROR, "revisit-truncated", view.record_id, str(exc))
    except (WarcIOError, WarcError) as exc:
        add(ERROR, "revisit-io", view.record_id, str(exc))


def _issue_to_error(issue: ValidationIssue) -> WarcError:
    if issue.code == "digest-mismatch":
        return DigestMismatchError(issue.record_id, "?", "?", "?")
    return WarcError(str(issue))
