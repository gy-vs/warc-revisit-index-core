"""Disk-backed WARC index: ingestion, deterministic queries, revisit resolution.

The index lives in a directory containing a single SQLite database
(``warcindex.db``).  Record metadata goes into the database; record blocks
stay in the original WARC files on disk and are addressed by
``(file, offset, length)`` at query time, so memory and index size stay
independent of WARC body size.
"""

from __future__ import annotations

import json
import os
import sqlite3
from typing import Iterator

from .errors import (
    DuplicateRecordIdError,
    FileChangedError,
    IndexFormatError,
    IndexNotFoundError,
    RecordNotFoundError,
    RevisitDigestMismatchError,
    RevisitTargetNotFoundError,
    RevisitTargetTruncatedError,
    TruncatedRecordError,
    UnsupportedRevisitProfileError,
    WarcIOError,
)
from .models import (
    IDENTICAL_PAYLOAD_PROFILES,
    SERVER_NOT_MODIFIED_PROFILES,
    RecordView,
)
from .reader import ResolvedPayload, materialize, stream_hash_payload
from ._util import normalize_record_id

_SCHEMA_VERSION = 1
_DB_NAME = "warcindex.db"

_SCHEMA = f"""
PRAGMA user_version = {_SCHEMA_VERSION};

CREATE TABLE IF NOT EXISTS files (
    id          INTEGER PRIMARY KEY,
    path        TEXT NOT NULL UNIQUE,
    size        INTEGER NOT NULL,
    added_order INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS records (
    record_id        TEXT PRIMARY KEY,
    record_type      TEXT NOT NULL,
    target_uri       TEXT,
    date             TEXT,
    epoch            REAL,
    digest_algo      TEXT,
    digest_value     TEXT,
    refers_to        TEXT,
    revisit_profile  TEXT,
    http_status      INTEGER,
    file_id          INTEGER NOT NULL REFERENCES files(id),
    offset           INTEGER NOT NULL,
    length           INTEGER NOT NULL,
    truncated        INTEGER NOT NULL,
    trunc_reason     TEXT,
    warnings         TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS ix_records_uri_date
    ON records(target_uri, epoch, record_id);
CREATE INDEX IF NOT EXISTS ix_records_date
    ON records(epoch, record_id);
CREATE INDEX IF NOT EXISTS ix_records_digest
    ON records(digest_value, record_id);
CREATE INDEX IF NOT EXISTS ix_records_refers
    ON records(refers_to);
CREATE INDEX IF NOT EXISTS ix_records_file
    ON records(file_id, offset);
"""


class WarcIndex:
    """A persistent, on-disk index of WARC records.

    Typical lifecycle::

        idx = WarcIndex.open_or_create("./idx")
        idx.add_path("./crawl-2026.warc")
        idx.save()

        # ... later, possibly in another process ...
        idx = WarcIndex.open("./idx")
        for view in idx.query(uri="https://example.com/"):
            payload = idx.resolve(view)
    """

    # ------------------------------------------------------------------ open

    def __init__(self, directory: str, *, create: bool) -> None:
        self.directory = os.path.abspath(directory)
        self._closed = False
        if create:
            os.makedirs(self.directory, exist_ok=True)
        db_path = os.path.join(self.directory, _DB_NAME)
        if not create and not os.path.isfile(db_path):
            raise IndexNotFoundError(f"no index found at {self.directory!r}")
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        if create:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
        else:
            self._check_schema()
        self._file_cache: dict[str, tuple[int, int]] = {}

    def _check_schema(self) -> None:
        try:
            version = self._conn.execute("PRAGMA user_version").fetchone()[0]
        except sqlite3.DatabaseError as exc:
            raise IndexFormatError(
                f"index database at {self.directory!r} is not readable: {exc}"
            ) from exc
        if version != _SCHEMA_VERSION:
            raise IndexFormatError(
                f"unsupported index schema version {version}; "
                f"this library supports {_SCHEMA_VERSION}"
            )

    @classmethod
    def open_or_create(cls, directory: str) -> "WarcIndex":
        return cls(directory, create=not os.path.isfile(os.path.join(directory, _DB_NAME)))

    @classmethod
    def create(cls, directory: str) -> "WarcIndex":
        return cls(directory, create=True)

    @classmethod
    def open(cls, directory: str) -> "WarcIndex":
        return cls(directory, create=False)

    def close(self) -> None:
        if not self._closed:
            self._conn.close()
            self._closed = True

    def __enter__(self) -> "WarcIndex":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------- ingestion

    def add_path(self, path: str, *, chunk_size: int = 1024 * 1024) -> int:
        """Index every record in the WARC file at *path*.

        Returns the number of records added.  Adding a file that was already
        indexed and has not changed is a no-op returning 0; adding the same
        path after its size changed raises :class:`FileChangedError`.
        """
        from .reader import iter_records

        path = os.path.abspath(path)
        size = _file_size(path)
        existing = self._lookup_file(path)
        if existing is not None:
            file_id, old_size = existing
            if old_size != size:
                raise FileChangedError(path, old_size, size)
            return 0
        file_id = self._insert_file(path, size)
        count = 0
        for info in iter_records(path, chunk_size=chunk_size):
            self._insert_record(file_id, info)
            count += 1
        self._conn.commit()
        return count

    def _insert_file(self, path: str, size: int) -> int:
        order = self._conn.execute(
            "SELECT COALESCE(MAX(added_order), 0) + 1 FROM files"
        ).fetchone()[0]
        cur = self._conn.execute(
            "INSERT INTO files(path, size, added_order) VALUES (?, ?, ?)",
            (path, size, order),
        )
        return cur.lastrowid

    def _lookup_file(self, path: str) -> tuple[int, int] | None:
        if path in self._file_cache:
            return self._file_cache[path]
        row = self._conn.execute(
            "SELECT id, size FROM files WHERE path = ?", (path,)
        ).fetchone()
        if row is None:
            return None
        result = (row["id"], row["size"])
        self._file_cache[path] = result
        return result

    def _insert_record(self, file_id: int, info) -> None:
        warnings = list(info.warnings)
        if (
            info.declared_payload_digest is not None
            and info.declared_payload_digest != info.computed_payload_digest
        ):
            warnings.append(
                "declared payload digest "
                f"{info.declared_payload_digest_algorithm}:{info.declared_payload_digest} "
                f"does not match computed "
                f"{info.computed_payload_digest_algorithm}:{info.computed_payload_digest}"
            )
        try:
            self._conn.execute(
                """
                INSERT INTO records(
                    record_id, record_type, target_uri, date, epoch,
                    digest_algo, digest_value, refers_to, revisit_profile,
                    http_status, file_id, offset, length, truncated,
                    trunc_reason, warnings
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    info.record_id,
                    info.record_type,
                    info.target_uri,
                    info.date,
                    info.epoch,
                    info.declared_payload_digest_algorithm
                        or info.computed_payload_digest_algorithm,
                    info.declared_payload_digest
                        if info.declared_payload_digest is not None
                        else info.computed_payload_digest,
                    info.refers_to,
                    info.revisit_profile,
                    info.http_status,
                    file_id,
                    info.offset,
                    info.length,
                    1 if info.truncated else 0,
                    info.trunc_reason,
                    json.dumps(warnings, ensure_ascii=False),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise DuplicateRecordIdError(info.record_id) from exc

    # ------------------------------------------------------------ save/sync

    def save(self) -> None:
        """Commit pending data and fsync the index to disk."""
        conn = self._conn
        conn.commit()
        # make sure committed pages are durable before returning
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.commit()
        db_path = os.path.join(self.directory, _DB_NAME)
        _fsync_path(db_path)

    # ---------------------------------------------------------------- queries

    def query(
        self,
        *,
        uri: str | None = None,
        date: str | None = None,
        record_id: str | None = None,
        payload_digest: str | None = None,
        record_type: str | None = None,
    ) -> list[RecordView]:
        """Look records up by URI, capture time, record id and/or digest.

        Multiple criteria are AND-ed.  Results are returned in a total,
        deterministic order: ``(target_uri, epoch, record_id)`` — captures of
        the same URI at different times stay distinct; ties beyond the
        timestamp break by record id.  Empty criteria returns every record in
        that order.
        """
        clauses: list[str] = []
        params: list = []
        if uri is not None:
            clauses.append("r.target_uri = ?")
            params.append(uri.strip())
        if date is not None:
            epoch = _query_date_to_epoch(date)
            if epoch is None:
                return []
            clauses.append("r.epoch = ?")
            params.append(epoch)
        if record_id is not None:
            clauses.append("r.record_id = ?")
            params.append(normalize_record_id(record_id))
        if payload_digest is not None:
            value = payload_digest.strip().upper()
            if ":" in value:
                _, _, value = value.partition(":")
            clauses.append("r.digest_value = ?")
            params.append(value)
        if record_type is not None:
            clauses.append("r.record_type = ?")
            params.append(record_type.strip().lower())
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (
            "SELECT r.*, f.path AS file_path FROM records r "
            "JOIN files f ON f.id = r.file_id"
            + where
            + " ORDER BY r.target_uri IS NULL, r.target_uri, "
              "r.epoch IS NULL, r.epoch, r.record_id"
        )
        return [_row_to_view(row) for row in self._conn.execute(sql, params)]

    def get(self, record_id: str) -> RecordView:
        """Return exactly one record by ``WARC-Record-ID`` or raise."""
        row = self._conn.execute(
            "SELECT r.*, f.path AS file_path FROM records r "
            "JOIN files f ON f.id = r.file_id WHERE r.record_id = ?",
            (normalize_record_id(record_id),),
        ).fetchone()
        if row is None:
            raise RecordNotFoundError(f"no record with id {record_id!r}")
        return _row_to_view(row)

    def __contains__(self, record_id: str) -> bool:
        try:
            self.get(record_id)
        except RecordNotFoundError:
            return False
        return True

    def __len__(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]

    def __iter__(self) -> Iterator[RecordView]:
        return iter(self.query())

    # ------------------------------------------------------------- resolve

    def resolve(self, ref: RecordView | str) -> ResolvedPayload:
        """Materialize a record's HTTP headers and body.

        For a *revisit* record the original target record is located in the
        index and its HTTP head/body returned instead — the result's
        ``payload_record_id`` names the record the body actually came from.

        Explicit failures (never silently returned as if normal):

        * :class:`TruncatedRecordError` — the record is truncated;
        * :class:`RevisitTargetNotFoundError` — the revisit's target record
          is absent from the index;
        * :class:`RevisitDigestMismatchError` — the revisit's declared payload
          digest does not match the target's;
        * :class:`RevisitTargetTruncatedError` — the target record is
          truncated;
        * :class:`UnsupportedRevisitProfileError` — unknown revisit profile.
        """
        view = ref if isinstance(ref, RecordView) else self.get(ref)
        self._ensure_file_ready(view)

        if view.record_type != "revisit":
            if view.truncated:
                raise TruncatedRecordError(view.record_id, view.trunc_reason or "unknown")
            return materialize(
                view.file_path, view.offset, view.length, expected_id=view.record_id
            )
        return self._resolve_revisit(view)

    def _resolve_revisit(self, view: RecordView) -> ResolvedPayload:
        if view.truncated:
            raise TruncatedRecordError(view.record_id, view.trunc_reason or "unknown")

        profile = (view.revisit_profile or "").strip()
        if profile in IDENTICAL_PAYLOAD_PROFILES:
            target = self._find_identical_payload_target(view)
        elif profile in SERVER_NOT_MODIFIED_PROFILES:
            target = self._find_server_not_modified_target(view)
        else:
            raise UnsupportedRevisitProfileError(profile or "(missing)")

        if target is None:
            raise RevisitTargetNotFoundError(view.record_id, view.refers_to)
        if target.truncated:
            raise RevisitTargetTruncatedError(
                target.record_id, target.trunc_reason or "unknown"
            )
        self._ensure_file_ready(target)

        # First pass: verify the bytes actually on disk against the digest the
        # revisit claims, using a throwaway stream so the caller still gets a
        # body positioned at the first byte.
        verifier = materialize(
            target.file_path,
            target.offset,
            target.length,
            expected_id=target.record_id,
        )
        algo = view.payload_digest_algorithm or target.payload_digest_algorithm
        try:
            if not (algo and view.payload_digest and target.payload_digest):
                # No digest on one side: provenance cannot be verified.
                raise RevisitDigestMismatchError(
                    view.record_id,
                    algo or "sha1",
                    view.payload_digest or "<missing>",
                    target.payload_digest or "<missing>",
                )
            if view.payload_digest != target.payload_digest:
                raise RevisitDigestMismatchError(
                    view.record_id,
                    algo,
                    view.payload_digest,
                    target.payload_digest,
                )
            actual = stream_hash_payload(verifier, algo)
            if actual != view.payload_digest:
                raise RevisitDigestMismatchError(
                    view.record_id, algo, view.payload_digest, actual
                )
        finally:
            verifier.close()

        # Second pass: a fresh, unconsumed body stream for the caller.
        resolved = materialize(
            target.file_path,
            target.offset,
            target.length,
            expected_id=target.record_id,
        )
        # Rewrite provenance onto the returned payload in place, keeping the
        # single open body stream (which reads from the target record).
        resolved.record_id = view.record_id
        resolved.record_type = "revisit"
        resolved.is_revisit = True
        resolved.payload_record_id = target.record_id
        return resolved

    def _find_identical_payload_target(self, view: RecordView) -> RecordView | None:
        """Find the same-URI response a digest revisit represents.

        Selection order: an explicit ``WARC-Refers-To`` pointer that is a
        compatible candidate, else the most recent earlier response for the
        same URI (digest equality is enforced afterwards during resolution
        and validation).
        """
        rows = self._conn.execute(
            """
            SELECT r.*, f.path AS file_path FROM records r
            JOIN files f ON f.id = r.file_id
            WHERE r.target_uri IS ?
              AND r.record_type = 'response'
              AND r.record_id != ?
              AND (r.epoch IS NULL OR r.epoch <= ?)
            ORDER BY r.epoch DESC, r.record_id
            """,
            (view.target_uri, view.record_id, view.epoch),
        ).fetchall()
        candidates = [_row_to_view(r) for r in rows]
        if view.refers_to:
            pointed = self._get_optional(view.refers_to)
            if pointed is not None and pointed.record_type == "response":
                return pointed
            if pointed is not None:
                return pointed
        return candidates[0] if candidates else self._get_optional(view.refers_to)

    def _find_server_not_modified_target(self, view: RecordView) -> RecordView | None:
        """Server-not-modified revisits name the target via WARC-Refers-To."""
        if not view.refers_to:
            # fall back to the most recent same-URI response
            rows = self._conn.execute(
                """
                SELECT r.*, f.path AS file_path FROM records r
                JOIN files f ON f.id = r.file_id
                WHERE r.target_uri IS ?
                  AND r.record_type = 'response'
                  AND (r.epoch IS NULL OR r.epoch <= ?)
                ORDER BY r.epoch DESC, r.record_id
                """,
                (view.target_uri, view.epoch),
            ).fetchall()
            candidates = [_row_to_view(r) for r in rows]
            return candidates[0] if candidates else None
        return self._get_optional(view.refers_to)

    def _get_optional(self, record_id: str | None) -> RecordView | None:
        if not record_id:
            return None
        row = self._conn.execute(
            "SELECT r.*, f.path AS file_path FROM records r "
            "JOIN files f ON f.id = r.file_id WHERE r.record_id = ?",
            (record_id,),
        ).fetchone()
        return _row_to_view(row) if row is not None else None

    def _ensure_file_ready(self, view: RecordView) -> None:
        row = self._conn.execute(
            "SELECT size FROM files WHERE path = ?", (view.file_path,)
        ).fetchone()
        if row is None:  # pragma: no cover - foreign key prevents this
            raise RecordNotFoundError(
                f"source file {view.file_path!r} is not registered in the index"
            )
        try:
            actual = _file_size(view.file_path)
        except WarcIOError:
            raise
        if actual != row["size"]:
            raise FileChangedError(view.file_path, row["size"], actual)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _row_to_view(row: sqlite3.Row) -> RecordView:
    try:
        warnings = tuple(json.loads(row["warnings"] or "[]"))
    except (ValueError, TypeError):
        warnings = ()
    return RecordView(
        record_id=row["record_id"],
        record_type=row["record_type"],
        target_uri=row["target_uri"],
        date=row["date"],
        epoch=row["epoch"],
        payload_digest=row["digest_value"],
        payload_digest_algorithm=row["digest_algo"],
        refers_to=row["refers_to"],
        revisit_profile=row["revisit_profile"],
        http_status=row["http_status"],
        file_path=row["file_path"],
        offset=row["offset"],
        length=row["length"],
        truncated=bool(row["truncated"]),
        trunc_reason=row["trunc_reason"],
        warnings=warnings,
    )


def _file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError as exc:
        raise WarcIOError(f"cannot stat WARC file {path!r}: {exc}") from exc


def _fsync_path(path: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _query_date_to_epoch(date: str) -> float | None:
    """Accept a WARC-Date string (any ISO form) or an epoch number."""
    date = date.strip()
    try:
        return float(date)
    except ValueError:
        pass
    from datetime import datetime, timezone

    try:
        dt = datetime.fromisoformat(date.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).timestamp()
