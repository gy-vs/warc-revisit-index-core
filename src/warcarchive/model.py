"""Core data model: record types, headers, handles and the warning catalog."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Iterator


class RecordType(str, Enum):
    """WARC record types recognised by the library (WARC 1.0/1.1)."""

    WARCINFO = "warcinfo"
    RESPONSE = "response"
    RESOURCE = "resource"
    REQUEST = "request"
    METADATA = "metadata"
    REVISIT = "revisit"
    CONVERSION = "conversion"
    CONTINUATION = "continuation"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, raw: str) -> "RecordType":
        try:
            return cls(raw.strip().lower())
        except ValueError:
            return cls.UNKNOWN


# Warning codes.  Kept as stable string constants so index consumers can
# pattern-match on them across versions.
W_BARE_LF = "bare-line-feed"
W_DUPLICATE_HEADER = "duplicate-header"
W_INVALID_DATE = "invalid-warc-date"
W_INVALID_DIGEST = "invalid-warc-digest"
W_MISSING_RECORD_ID = "missing-record-id"
W_MISSING_URI = "missing-target-uri"
W_MISSING_DATE = "missing-warc-date"
W_UNKNOWN_TYPE = "unknown-record-type"
W_WARC_VERSION = "unexpected-warc-version"
W_HTTP_PREFIX_LIMIT = "http-prefix-scan-limit"
W_NOT_HTTP = "block-is-not-http"
W_RECORD_TRUNCATED = "record-truncated"
W_MISSING_TERMINATOR = "missing-record-terminator"
W_BAD_TERMINATOR = "bad-record-terminator"
W_GZIP_TRUNCATED = "gzip-member-truncated"
W_GZIP_MEMBER_CRC = "gzip-member-crc-error"
W_HTTP_MALFORMED = "malformed-http-head"
W_CONTENT_LENGTH_MISMATCH = "http-content-length-mismatch"


class HeaderMap:
    """Case-insensitive, order-preserving multi-aware WARC header map.

    Duplicate header names are kept (first value wins on lookup) and reported
    via the duplicate-header warning by the parser.
    """

    __slots__ = ("_pairs",)

    def __init__(self, pairs: list[tuple[str, str]] | None = None) -> None:
        self._pairs: list[tuple[str, str]] = pairs or []

    def get(self, name: str, default: str | None = None) -> str | None:
        lowered = name.lower()
        for key, value in self._pairs:
            if key.lower() == lowered:
                return value
        return default

    def get_all(self, name: str) -> list[str]:
        lowered = name.lower()
        return [v for k, v in self._pairs if k.lower() == lowered]

    def names(self) -> list[str]:
        return [k for k, _ in self._pairs]

    def pairs(self) -> list[tuple[str, str]]:
        return list(self._pairs)

    def __contains__(self, name: str) -> bool:
        return self.get(name) is not None

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(self._pairs)

    def __len__(self) -> int:
        return len(self._pairs)


@dataclass(frozen=True, slots=True)
class WarcHead:
    """Parsed WARC record header (everything before the first blank line)."""

    version: str
    fields: HeaderMap
    raw: bytes

    def get(self, name: str) -> str | None:
        return self.fields.get(name)


def parse_warc_date(raw: str | None) -> datetime | None:
    """Parse a WARC-Date (RFC 3339 / ISO 8601) into an aware UTC datetime."""
    if not raw:
        return None
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_record_id(raw: str | None) -> str | None:
    """Strip ``<...>`` angle brackets and whitespace from a WARC-Record-ID."""
    if raw is None:
        return None
    value = raw.strip()
    if len(value) >= 2 and value.startswith("<") and value.endswith(">"):
        value = value[1:-1]
    return value.strip() or None


def normalize_uri(raw: str | None) -> str | None:
    if raw is None:
        return None
    value = raw.strip()
    return value or None


TRUNCATION_REASONS = {
    "length",
    "time",
    "disconnect",
    "unspecified",
}


def truncation_reason(head: WarcHead) -> str | None:
    """Return the WARC-Truncated reason if the record is marked truncated."""
    raw = head.get("WARC-Truncated")
    if raw is None:
        return None
    return raw.strip().lower() or "unspecified"


@dataclass(frozen=True, slots=True)
class RecordHandle:
    """One parsed WARC record: metadata plus a pointer back to its bytes.

    Nothing from the record *block* is retained here, so a stream of many
    multi-gigabyte records keeps a flat, tiny memory footprint.
    """

    record_id: str | None
    record_type: RecordType
    target_uri: str | None
    date: datetime | None
    payload_digest: str | None
    """canonical ``algo:value`` form, or the raw string if unparseable"""
    block_digest: str | None
    refers_to: str | None
    profile: str | None
    ip_address: str | None
    truncated: str | None
    warcinfo_id: str | None
    http_status: int | None
    http_head: bytes
    """raw HTTP start-line + header bytes for response/revisit (else b'')"""
    payload_offset: int
    """offset of the payload within the (uncompressed) record block"""
    http_chunked: bool
    content_length: int
    """declared WARC Content-Length / actual block bytes consumed"""

    # Location in the original file.
    offset: int
    """offset where the record (WARC header) starts"""
    length: int
    """total record length, including header, block and CRLFCRLF tail"""
    head_length: int
    block_length: int
    tail_length: int

    # Gzip bookkeeping; None for plain WARCs.
    compressed_offset: int | None = None
    compressed_length: int | None = None
    member_logical_offset: int | None = None
    """logical (uncompressed) offset of the containing gzip member's start;
    equals the record's own logical offset for one-record members"""
    gzip_crc_ok: bool = True

    warnings: tuple[str, ...] = field(default_factory=tuple)
