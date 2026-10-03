"""Persistent index, query API and revisit resolution.

The index lives in a SQLite database file, so building it and later opening
it from a *different* process yields identical query results.  Only record
metadata and byte coordinates are persisted — never payloads — and ingest is
fully streaming.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Iterator, Sequence

from .digest import DigestHasher, parse_digest
from .errors import (
    DigestMismatchError,
    DuplicateRecordIdError,
    IndexConsistencyError,
    RecordNotFoundError,
    RevisitDigestMismatchError,
    RevisitProfileError,
    RevisitTargetNotFoundError,
    RevisitTruncatedError,
)
from .model import RecordHandle, RecordType
from .parser import RecordFeeder
from .storage import FileSource, iter_payload, read_payload

_SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    id          INTEGER PRIMARY KEY,
    path        TEXT NOT NULL UNIQUE,
    file_size   INTEGER NOT NULL,
    compression INTEGER NOT NULL,          -- 0 plain, 1 gzip
    added_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
    id                INTEGER PRIMARY KEY,
    record_id         TEXT,
    source_id         INTEGER NOT NULL REFERENCES sources(id),
    record_type       TEXT NOT NULL,
    target_uri        TEXT,
    date_text         TEXT,
    payload_digest    TEXT,
    block_digest      TEXT,
    refers_to         TEXT,
    profile           TEXT,
    ip_address        TEXT,
    truncated         TEXT,
    warcinfo_id       TEXT,
    http_status       INTEGER,
    http_head         BLOB,
    payload_offset    INTEGER NOT NULL,
    http_chunked      INTEGER NOT NULL,
    content_length    INTEGER NOT NULL,
    offset            INTEGER NOT NULL,
    length            INTEGER NOT NULL,
    head_length       INTEGER NOT NULL,
    block_length      INTEGER NOT NULL,
    tail_length       INTEGER NOT NULL,
    compressed_offset INTEGER,
    compressed_length INTEGER,
    member_logical_offset INTEGER,
    gzip_crc_ok       INTEGER NOT NULL DEFAULT 1,
    warnings          TEXT NOT NULL DEFAULT '[]',
    ord_in_source     INTEGER NOT NULL,
    UNIQUE(source_id, record_id)
);
CREATE INDEX IF NOT EXISTS idx_records_uri_date
    ON records(target_uri, date_text, id);
CREATE INDEX IF NOT EXISTS idx_records_digest
    ON records(payload_digest);
CREATE INDEX IF NOT EXISTS idx_records_record_id
    ON records(record_id);
CREATE INDEX IF NOT EXISTS idx_records_refers
    ON records(refers_to);
"""

_PROFILE_IDENTICAL = (
    "http://netpreserve.org/warc/1.0/revisit/identical-payload-digest"
)
_PROFILE_SERVER_NOT_MODIFIED = (
    "http://netpreserve.org/warc/1.0/revisit/server-not-modified"
)
_KNOWN_PROFILES = {_PROFILE_IDENTICAL, _PROFILE_SERVER_NOT_MODIFIED}


def _dt_text(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _dt_load(text: str | None) -> datetime | None:
    if text is None:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


# ---------------------------------------------------------------------------
# Result view
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PayloadResult:
    """Resolved body returned for a response or revisit capture."""

    http_head: bytes
    """original HTTP status line + headers (from the origin record)"""
    body: bytes
    payload_digest: str | None
    """canonical digest of the body, when computable"""
    origin_record_id: str | None
    """id of the record the bytes came from (self for plain responses)"""
    origin_source_path: str
    origin_offset: int
    origin_length: int
    warnings: tuple[str, ...]


class RecordView:
    """One index row plus the methods to read its underlying bytes.

    ``offset`` / ``length`` describe where the record lives in the *original
    WARC file* (compressed coordinates for gzip WARCs).  ``warnings`` are the
    parser warnings collected at ingest.
    """

    def __init__(self, index: "Index", handle: RecordHandle, source_id: int,
                 source_path: str, row_id: int) -> None:
        self._index = index
        self._handle = handle
        self._source_id = source_id
        self.source_path = source_path
        self._row_id = row_id

    # -- metadata ----------------------------------------------------------

    @property
    def handle(self) -> RecordHandle:
        return self._handle

    @property
    def record_id(self) -> str | None:
        return self._handle.record_id

    @property
    def record_type(self) -> RecordType:
        return self._handle.record_type

    @property
    def target_uri(self) -> str | None:
        return self._handle.target_uri

    @property
    def date(self) -> datetime | None:
        return self._handle.date

    @property
    def payload_digest(self) -> str | None:
        return self._handle.payload_digest

    @property
    def truncated(self) -> str | None:
        return self._handle.truncated

    @property
    def offset(self) -> int:
        return self._handle.offset

    @property
    def length(self) -> int:
        return self._handle.length

    @property
    def compressed_offset(self) -> int | None:
        return self._handle.compressed_offset

    @property
    def compressed_length(self) -> int | None:
        return self._handle.compressed_length

    @property
    def warnings(self) -> tuple[str, ...]:
        return self._handle.warnings

    @property
    def http_status(self) -> int | None:
        return self._handle.http_status

    @property
    def http_head(self) -> bytes:
        return self._handle.http_head

    @property
    def is_revisit(self) -> bool:
        return self._handle.record_type is RecordType.REVISIT

    def __repr__(self) -> str:
        return (
            f"RecordView(type={self._handle.record_type.value!r}, "
            f"uri={self.target_uri!r}, date={self.date}, "
            f"id={self.record_id!r})"
        )

    # -- raw access --------------------------------------------------------

    def _source(self) -> FileSource:
        return self._index.get_source(self._source_id)

    def iter_block(self) -> Iterator[bytes]:
        from .storage import iter_block

        yield from iter_block(self._handle, self._source())

    def block_bytes(self) -> bytes:
        return b"".join(self.iter_block())

    def iter_payload(self) -> Iterator[bytes]:
        yield from iter_payload(self._handle, self._source())

    def payload_bytes(self) -> bytes:
        return read_payload(self._handle, self._source())

    # -- revisit resolution ------------------------------------------------

    def resolve(self) -> PayloadResult:
        """Return the replayable HTTP head+body for this capture.

        For ``response`` records this is the record's own content.  For
        ``revisit`` records the linked/ matched original is located and its
        head and body are returned.  Failures raise the specific
        :mod:`warcarchive.errors` exceptions — never a deceptively empty
        result.
        """
        return self._index.resolve_view(self)


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Query:
    """Filter for :meth:`Index.query`.  All fields are optional / additive."""

    uri: str | None = None
    record_id: str | None = None
    payload_digest: str | None = None
    record_type: str | RecordType | None = None
    from_date: datetime | None = None
    to_date: datetime | None = None
    limit: int | None = None


# ---------------------------------------------------------------------------
# Index
# ---------------------------------------------------------------------------


_COLUMNS = (
    "record_id", "record_type", "target_uri", "date_text", "payload_digest",
    "block_digest", "refers_to", "profile", "ip_address", "truncated",
    "warcinfo_id", "http_status", "http_head", "payload_offset",
    "http_chunked", "content_length", "offset", "length", "head_length",
    "block_length", "tail_length", "compressed_offset", "compressed_length",
    "member_logical_offset", "gzip_crc_ok", "warnings",
)


class Index:
    """Queryable, disk-backed record index.

    Open an existing database with :meth:`open` or create a new one with
    :meth:`create`.  ``":memory:"`` builds a non-persistent index (useful for
    tests and one-shot validation).
    """

    def __init__(self, conn: sqlite3.Connection, path: str | None) -> None:
        self._conn = conn
        self.path = path
        self._sources: dict[int, FileSource] = {}

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    def create(cls, db_path: str | os.PathLike[str] = ":memory:") -> "Index":
        path = None if str(db_path) == ":memory:" else os.fspath(db_path)
        if path is not None:
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".",
                        exist_ok=True)
        conn = sqlite3.connect(path or ":memory:", check_same_thread=False)
        conn.row_factory = sqlite3.Row
        _configure(conn)
        conn.executescript(_SCHEMA)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)"
        )
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)",
            (str(_SCHEMA_VERSION),),
        )
        conn.commit()
        return cls(conn, path)

    @classmethod
    def open(cls, db_path: str | os.PathLike[str]) -> "Index":
        path = os.fspath(db_path)
        if not os.path.isfile(path):
            raise IndexConsistencyError(f"index file not found: {path}")
        conn = sqlite3.connect(path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        _configure(conn)
        try:
            version = conn.execute(
                "SELECT value FROM meta WHERE key='schema_version'"
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise IndexConsistencyError(f"not a warcarchive index: {path}") from exc
        if version is None or version["value"] != str(_SCHEMA_VERSION):
            raise IndexConsistencyError(
                f"unsupported index schema version in {path}: "
                f"{version['value'] if version else 'missing'}"
            )
        return cls(conn, path)

    def close(self) -> None:
        try:
            if self.path is not None:
                self._conn.commit()
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            self._conn.close()

    def __enter__(self) -> "Index":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def save(self) -> None:
        """Flush pending rows to disk (no-op logically, commits the txn)."""
        self._conn.commit()

    # -- ingest ------------------------------------------------------------

    def add_source(self, path: str | os.PathLike[str],
                   compression: str = "auto",
                   chunk_size: int = 1 << 20) -> list[RecordView]:
        """Stream-parse a WARC file and index every record.

        Memory use stays flat regardless of file size.  Re-adding the same
        path replaces its previous rows.
        """
        file_path = os.fspath(path)
        if not os.path.isfile(file_path):
            from .errors import SourceNotFoundError

            raise SourceNotFoundError(file_path)
        size = os.path.getsize(file_path)
        feeder = RecordFeeder(compression=compression)
        handles: list[RecordHandle] = []
        with open(file_path, "rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                handles.extend(feeder.feed(chunk))
        handles.extend(feeder.finish())

        is_gzip = any(h.compressed_offset is not None for h in handles)
        source_id = self._register_source(file_path, size, 1 if is_gzip else 0)
        self._replace_rows(source_id, handles)
        self._conn.commit()
        return self._views_for_source(source_id)

    def add_stream(
        self,
        chunks: Iterable[bytes],
        source_path: str = "<stream>",
        compression: str = "auto",
        file_size: int | None = None,
    ) -> list[RecordView]:
        """Index WARC bytes arriving as arbitrary chunks (one-shot).

        ``source_path`` is where the bytes live for later payload reads; if
        the stream has no backing file, payload reads will fail until a
        matching source path is registered.
        """
        feeder = RecordFeeder(compression=compression)
        handles: list[RecordHandle] = []
        total = 0
        for chunk in chunks:
            total += len(chunk)
            handles.extend(feeder.feed(chunk))
        handles.extend(feeder.finish())

        is_gzip = any(h.compressed_offset is not None for h in handles)
        source_id = self._register_source(
            source_path,
            file_size if file_size is not None else total,
            1 if is_gzip else 0,
            replace=False,
        )
        self._insert_rows(source_id, handles)
        self._conn.commit()
        return self._views_for_source(source_id)

    def _register_source(
        self, path: str, size: int, compression: int, replace: bool = True
    ) -> int:
        now = _dt_text(datetime.now(timezone.utc))
        if replace:
            row = self._conn.execute(
                "SELECT id FROM sources WHERE path=?", (path,)
            ).fetchone()
            if row is not None:
                old_id = row["id"]
                self._conn.execute("DELETE FROM records WHERE source_id=?", (old_id,))
                self._conn.execute("DELETE FROM sources WHERE id=?", (old_id,))
        cur = self._conn.execute(
            "INSERT INTO sources(path, file_size, compression, added_at) "
            "VALUES(?,?,?,?)",
            (path, size, compression, now),
        )
        return int(cur.lastrowid)

    def _replace_rows(self, source_id: int, handles: Sequence[RecordHandle]) -> None:
        self._insert_rows(source_id, handles)

    def _insert_rows(self, source_id: int, handles: Sequence[RecordHandle]) -> None:
        rows = []
        for ordinal, handle in enumerate(handles):
            rows.append((
                handle.record_id,
                source_id,
                handle.record_type.value,
                handle.target_uri,
                _dt_text(handle.date),
                handle.payload_digest,
                handle.block_digest,
                handle.refers_to,
                handle.profile,
                handle.ip_address,
                handle.truncated,
                handle.warcinfo_id,
                handle.http_status,
                sqlite3.Binary(handle.http_head),
                handle.payload_offset,
                1 if handle.http_chunked else 0,
                handle.content_length,
                handle.offset,
                handle.length,
                handle.head_length,
                handle.block_length,
                handle.tail_length,
                handle.compressed_offset,
                handle.compressed_length,
                handle.member_logical_offset,
                1 if handle.gzip_crc_ok else 0,
                json.dumps(list(handle.warnings), separators=(",", ":")),
                ordinal,
            ))
        # Column order must match the tuple built above.
        cols = (
            "record_id", "source_id",
            "record_type", "target_uri", "date_text", "payload_digest",
            "block_digest", "refers_to", "profile", "ip_address",
            "truncated", "warcinfo_id", "http_status", "http_head",
            "payload_offset", "http_chunked", "content_length", "offset",
            "length", "head_length", "block_length", "tail_length",
            "compressed_offset", "compressed_length",
            "member_logical_offset", "gzip_crc_ok",
            "warnings", "ord_in_source",
        )
        placeholders = ",".join("?" for _ in cols)
        try:
            self._conn.executemany(
                f"INSERT INTO records({','.join(cols)}) VALUES({placeholders})",
                rows,
            )
        except sqlite3.IntegrityError as exc:
            raise DuplicateRecordIdError(str(exc)) from exc

    # -- sources -----------------------------------------------------------

    def get_source(self, source_id: int) -> FileSource:
        cached = self._sources.get(source_id)
        if cached is not None:
            return cached
        row = self._conn.execute(
            "SELECT path FROM sources WHERE id=?", (source_id,)
        ).fetchone()
        if row is None:
            raise IndexConsistencyError(f"source id {source_id} missing")
        source = FileSource(row["path"])
        self._sources[source_id] = source
        return source

    def sources(self) -> list[tuple[int, str, int]]:
        return [
            (r["id"], r["path"], r["file_size"])
            for r in self._conn.execute(
                "SELECT id, path, file_size FROM sources ORDER BY id"
            )
        ]

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM records").fetchone()[0])

    # -- query -------------------------------------------------------------

    def query(self, query: Query | None = None, **kwargs: object) -> list[RecordView]:
        """Run a query and return views in a fixed, reproducible order.

        Sorting is always ``(target_uri, date, source, in-file order)``, so
        two captures of the same URI at different times are distinct rows and
        identical criteria return identical orderings across processes.
        """
        q = query if query is not None else Query(
            **{k: v for k, v in kwargs.items() if v is not None}
        )
        where: list[str] = []
        params: list[object] = []
        if q.uri is not None:
            where.append("target_uri = ?")
            params.append(q.uri)
        if q.record_id is not None:
            from .model import normalize_record_id

            where.append("record_id = ?")
            params.append(normalize_record_id(q.record_id))
        if q.payload_digest is not None:
            canonical = _canon_query_digest(q.payload_digest)
            where.append("payload_digest = ?")
            params.append(canonical)
        if q.record_type is not None:
            rtype = (
                q.record_type
                if isinstance(q.record_type, RecordType)
                else RecordType.parse(str(q.record_type))
            )
            where.append("record_type = ?")
            params.append(rtype.value)
        if q.from_date is not None:
            where.append("date_text >= ?")
            params.append(_dt_text(q.from_date))
        if q.to_date is not None:
            where.append("date_text <= ?")
            params.append(_dt_text(q.to_date))

        sql = (
            "SELECT * FROM records "
            + ("WHERE " + " AND ".join(where) + " " if where else "")
            # Records lacking a parseable date sort last but still
            # deterministically via source/ordinal/id.
            + "ORDER BY target_uri, "
              "(date_text IS NULL), date_text, source_id, ord_in_source, id"
        )
        if q.limit is not None:
            sql += f" LIMIT {int(q.limit)}"
        rows = self._conn.execute(sql, params).fetchall()
        return [self._view_from_row(row) for row in rows]

    def get_by_id(self, record_id: str) -> RecordView:
        from .model import normalize_record_id

        rid = normalize_record_id(record_id)
        row = self._conn.execute(
            "SELECT * FROM records WHERE record_id=? "
            "ORDER BY target_uri, (date_text IS NULL), date_text, source_id, ord_in_source, id",
            (rid,),
        ).fetchone()
        if row is None:
            raise RecordNotFoundError(f"record id not found: {record_id!r}")
        return self._view_from_row(row)

    def __len__(self) -> int:
        return self.count()

    # -- revisit resolution ------------------------------------------------

    def resolve_view(self, view: RecordView) -> PayloadResult:
        handle = view.handle
        if handle.record_type is RecordType.RESPONSE:
            return self._payload_result(view, handle, view.source_path,
                                        origin_id=handle.record_id)
        if handle.record_type is not RecordType.REVISIT:
            from .errors import InvalidRecordTypeError

            raise InvalidRecordTypeError(
                f"resolve() expects response/revisit, got "
                f"{handle.record_type.value!r}"
            )
        if handle.truncated:
            raise RevisitTruncatedError(
                f"revisit {handle.record_id} is marked truncated "
                f"({handle.truncated})"
            )
        origin = self._find_revisit_origin(handle)
        origin_view = self._view_from_row(origin)
        origin_handle = origin_view.handle
        if origin_handle.truncated:
            raise RevisitTruncatedError(
                f"revisit {handle.record_id} resolves to truncated origin "
                f"{origin_handle.record_id} ({origin_handle.truncated})"
            )
        if origin_handle.record_type is not RecordType.RESPONSE:
            raise RevisitTargetNotFoundError(
                f"revisit {handle.record_id} resolves to non-response "
                f"record {origin_handle.record_id} "
                f"({origin_handle.record_type.value})"
            )
        return self._payload_result(
            origin_view,
            origin_handle,
            origin_view.source_path,
            origin_id=origin_handle.record_id,
            revisit=view,
        )

    def _find_revisit_origin(self, revisit: RecordHandle) -> sqlite3.Row:
        # 1) Explicit WARC-Refers-To wins whenever it points at a response.
        if revisit.refers_to:
            row = self._conn.execute(
                "SELECT * FROM records WHERE record_id=? AND record_type='response'",
                (revisit.refers_to,),
            ).fetchone()
            if row is None:
                raise RevisitTargetNotFoundError(
                    f"revisit {revisit.record_id}: WARC-Refers-To "
                    f"{revisit.refers_to!r} does not resolve to a response"
                )
            self._check_revisit_match(revisit, row)
            return row

        # 2) Profile-driven URI + payload-digest lookup.
        profile = (revisit.profile or "").strip()
        if profile not in _KNOWN_PROFILES:
            raise RevisitProfileError(
                f"revisit {revisit.record_id}: unsupported/missing profile "
                f"{profile!r} and no WARC-Refers-To"
            )
        if not revisit.target_uri:
            raise RevisitProfileError(
                f"revisit {revisit.record_id} has no WARC-Target-URI"
            )

        if profile == _PROFILE_IDENTICAL:
            if not revisit.payload_digest:
                raise RevisitProfileError(
                    f"identical-payload revisit {revisit.record_id} has no "
                    "WARC-Payload-Digest"
                )
            row = self._conn.execute(
                "SELECT * FROM records "
                "WHERE target_uri=? AND record_type='response' "
                "AND payload_digest=? "
                "ORDER BY (date_text IS NULL), date_text DESC, source_id, ord_in_source, id "
                "LIMIT 1",
                (revisit.target_uri, revisit.payload_digest),
            ).fetchone()
            if row is None:
                raise RevisitTargetNotFoundError(
                    f"revisit {revisit.record_id}: no response for "
                    f"{revisit.target_uri} with digest "
                    f"{revisit.payload_digest}"
                )
            self._check_revisit_match(revisit, row)
            return row

        # server-not-modified: digest is usually absent; match on URI and
        # take the closest prior capture.
        rows = self._conn.execute(
            "SELECT * FROM records WHERE target_uri=? AND record_type='response' "
            "ORDER BY (date_text IS NULL), date_text DESC, source_id, ord_in_source, id",
            (revisit.target_uri,),
        ).fetchall()
        if revisit.date is not None:
            rows = [r for r in rows
                    if _dt_load(r["date_text"]) is not None
                    and _dt_load(r["date_text"]) <= revisit.date] or rows
        if not rows:
            raise RevisitTargetNotFoundError(
                f"revisit {revisit.record_id}: no prior response for "
                f"{revisit.target_uri}"
            )
        row = rows[0]
        self._check_revisit_match(revisit, row)
        return row

    def _check_revisit_match(
        self, revisit: RecordHandle, candidate: sqlite3.Row
    ) -> None:
        if candidate["target_uri"] != revisit.target_uri:
            raise RevisitDigestMismatchError(
                expected=revisit.target_uri or "",
                actual=candidate["target_uri"] or "",
                record_id=candidate["record_id"],
            )
        if revisit.payload_digest:
            candidate_digest = candidate["payload_digest"]
            if not _digests_equal(revisit.payload_digest, candidate_digest):
                raise RevisitDigestMismatchError(
                    expected=revisit.payload_digest,
                    actual=candidate_digest or "",
                    record_id=candidate["record_id"],
                )

    def _payload_result(
        self,
        view: RecordView,
        handle: RecordHandle,
        source_path: str,
        origin_id: str | None,
        revisit: RecordView | None = None,
    ) -> PayloadResult:
        from .storage import iter_payload

        source = self.get_source(view._source_id)
        hasher = DigestHasher("sha1")
        chunks: list[bytes] = []
        size = 0
        for chunk in iter_payload(handle, source):
            hasher.update(chunk)
            chunks.append(chunk)
            size += len(chunk)
        body = b"".join(chunks)
        computed = str(hasher.digest())
        declared = handle.payload_digest
        if declared and not _digests_equal(declared, computed):
            raise DigestMismatchError(declared, computed)
        if handle.compressed_offset is not None:
            origin_offset = handle.compressed_offset
            origin_length = handle.compressed_length or handle.length
        else:
            origin_offset = handle.offset
            origin_length = handle.length
        warning_set = set(handle.warnings)
        if revisit is not None:
            warning_set.update(revisit.warnings)
        return PayloadResult(
            http_head=handle.http_head,
            body=body,
            payload_digest=declared or computed,
            origin_record_id=origin_id,
            origin_source_path=source_path,
            origin_offset=origin_offset,
            origin_length=origin_length or 0,
            warnings=tuple(sorted(warning_set)),
        )

    # -- row mapping -------------------------------------------------------

    def _view_from_row(self, row: sqlite3.Row) -> RecordView:
        handle = RecordHandle(
            record_id=row["record_id"],
            record_type=RecordType.parse(row["record_type"]),
            target_uri=row["target_uri"],
            date=_dt_load(row["date_text"]),
            payload_digest=row["payload_digest"],
            block_digest=row["block_digest"],
            refers_to=row["refers_to"],
            profile=row["profile"],
            ip_address=row["ip_address"],
            truncated=row["truncated"],
            warcinfo_id=row["warcinfo_id"],
            http_status=row["http_status"],
            http_head=bytes(row["http_head"] or b""),
            payload_offset=row["payload_offset"],
            http_chunked=bool(row["http_chunked"]),
            content_length=row["content_length"],
            offset=row["offset"],
            length=row["length"],
            head_length=row["head_length"],
            block_length=row["block_length"],
            tail_length=row["tail_length"],
            compressed_offset=row["compressed_offset"],
            compressed_length=row["compressed_length"],
            member_logical_offset=row["member_logical_offset"],
            gzip_crc_ok=bool(row["gzip_crc_ok"]),
            warnings=tuple(json.loads(row["warnings"] or "[]")),
        )
        return RecordView(
            self, handle, source_id=row["source_id"],
            source_path=self._source_path(row["source_id"]),
            row_id=row["id"],
        )

    def _source_path(self, source_id: int) -> str:
        row = self._conn.execute(
            "SELECT path FROM sources WHERE id=?", (source_id,)
        ).fetchone()
        if row is None:
            raise IndexConsistencyError(f"source id {source_id} missing")
        return row["path"]

    def _views_for_source(self, source_id: int) -> list[RecordView]:
        rows = self._conn.execute(
            "SELECT * FROM records WHERE source_id=? "
            "ORDER BY target_uri, (date_text IS NULL), date_text, source_id, ord_in_source, id",
            (source_id,),
        ).fetchall()
        return [self._view_from_row(row) for row in rows]


def _configure(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA temp_store=MEMORY")


def _canon_query_digest(raw: str) -> str:
    from .digest import normalize_digest

    canonical = normalize_digest(raw)
    return canonical if canonical is not None else raw.strip()


def _digests_equal(a: str | None, b: str | None) -> bool:
    if a is None or b is None:
        return False
    da, db_ = parse_digest(a), parse_digest(b)
    if da is None or db_ is None:
        return a.strip().upper() == b.strip().upper()
    return da.matches(db_)
