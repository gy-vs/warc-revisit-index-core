"""Index/record validation entry points.

``validate`` re-reads record blocks from disk and checks:

* declared WARC-Payload-Digest against the freshly computed payload digest;
* revisit records against the record they resolve to (missing target, digest
  mismatch, truncation are all reported as issues, not raised);
* truncation flags and gzip integrity recorded at ingest.

Validation is a streaming generator, so validating a multi-gigabyte WARC
does not load it into memory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

from .digest import DigestHasher, parse_digest
from .errors import (
    RevisitError,
    SourceNotFoundError,
    StorageError,
    UnknownDigestError,
    WarcError,
)
from .index import Index, RecordView
from .model import RecordType

# Issue severity / code constants.
ISSUE_PAYLOAD_DIGEST_MISMATCH = "payload-digest-mismatch"
ISSUE_BLOCK_UNREADABLE = "block-unreadable"
ISSUE_RECORD_TRUNCATED = "record-truncated"
ISSUE_GZIP_TRUNCATED = "gzip-member-truncated"
ISSUE_REVISIT_UNRESOLVABLE = "revisit-unresolvable"
ISSUE_REVISIT_DIGEST_MISMATCH = "revisit-digest-mismatch"
ISSUE_SOURCE_MISSING = "source-missing"
ISSUE_PARSE_WARNING = "parse-warning"
ISSUE_UNKNOWN_DIGEST = "unknown-digest-algorithm"


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    code: str
    record_id: str | None
    target_uri: str | None
    detail: str


@dataclass(slots=True)
class ValidationReport:
    """Aggregate result of an index validation pass."""

    checked: int = 0
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.issues

    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.code != ISSUE_PARSE_WARNING]

    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.code == ISSUE_PARSE_WARNING]


def validate(
    index: Index,
    verify_payloads: bool = True,
    verify_revisits: bool = True,
    include_parse_warnings: bool = True,
) -> ValidationReport:
    """Validate every record in ``index``; returns an aggregate report."""
    report = ValidationReport()
    for issue in iter_issues(
        index,
        verify_payloads=verify_payloads,
        verify_revisits=verify_revisits,
        include_parse_warnings=include_parse_warnings,
    ):
        report.issues.append(issue)
    report.checked = index.count()
    return report


def iter_issues(
    index: Index,
    verify_payloads: bool = True,
    verify_revisits: bool = True,
    include_parse_warnings: bool = True,
) -> Iterator[ValidationIssue]:
    """Stream validation issues record by record."""
    views = index.query()
    for view in views:
        handle = view.handle
        rid = handle.record_id
        uri = handle.target_uri

        for code in handle.warnings:
            if include_parse_warnings:
                yield ValidationIssue(
                    ISSUE_PARSE_WARNING,
                    rid,
                    uri,
                    f"parser warning: {code}",
                )

        if not handle.gzip_crc_ok:
            yield ValidationIssue(
                ISSUE_GZIP_TRUNCATED, rid, uri,
                "gzip member truncated or CRC failure",
            )
        if handle.truncated:
            yield ValidationIssue(
                ISSUE_RECORD_TRUNCATED, rid, uri,
                f"WARC-Truncated: {handle.truncated}",
            )

        if verify_revisits and handle.record_type is RecordType.REVISIT:
            yield from _validate_revisit(index, view)

        if (
            verify_payloads
            and handle.record_type
            in (RecordType.RESPONSE, RecordType.RESOURCE, RecordType.METADATA)
            and not handle.truncated
        ):
            yield from _validate_payload(view)


def _validate_payload(view: RecordView) -> Iterator[ValidationIssue]:
    handle = view.handle
    declared = handle.payload_digest
    algo = "sha1"
    if declared:
        parsed = None
        try:
            parsed = parse_digest(declared)
        except UnknownDigestError:
            yield ValidationIssue(
                ISSUE_UNKNOWN_DIGEST, handle.record_id, handle.target_uri,
                f"cannot parse declared digest: {declared!r}",
            )
            return
        if parsed is not None:
            algo = parsed.algo

    try:
        hasher = DigestHasher(algo)
        for chunk in view.iter_payload():
            hasher.update(chunk)
        computed = str(hasher.digest())
    except SourceNotFoundError as exc:
        yield ValidationIssue(
            ISSUE_SOURCE_MISSING, handle.record_id, handle.target_uri, str(exc)
        )
        return
    except StorageError as exc:
        yield ValidationIssue(
            ISSUE_BLOCK_UNREADABLE, handle.record_id, handle.target_uri, str(exc)
        )
        return

    if declared and parsed is not None and computed != str(parsed):
        yield ValidationIssue(
            ISSUE_PAYLOAD_DIGEST_MISMATCH,
            handle.record_id,
            handle.target_uri,
            f"declared={declared} computed={computed}",
        )


def _validate_revisit(
    index: Index, view: RecordView
) -> Iterator[ValidationIssue]:
    handle = view.handle
    try:
        index.resolve_view(view)
    except RevisitError as exc:
        yield ValidationIssue(
            ISSUE_REVISIT_UNRESOLVABLE,
            handle.record_id,
            handle.target_uri,
            str(exc),
        )
    except StorageError as exc:
        yield ValidationIssue(
            ISSUE_BLOCK_UNREADABLE,
            handle.record_id,
            handle.target_uri,
            str(exc),
        )
    except WarcError as exc:
        yield ValidationIssue(
            ISSUE_REVISIT_UNRESOLVABLE,
            handle.record_id,
            handle.target_uri,
            str(exc),
        )
