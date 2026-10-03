"""Core data structures: record types, header maps, events and query views."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

# WARC record types this library recognises (WARC 1.0/1.1 §6).
WARCINFO = "warcinfo"
RESPONSE = "response"
REVISIT = "revisit"
METADATA = "metadata"
REQUEST = "request"
RESOURCE = "resource"
CONVERSION = "conversion"
CONTINUATION = "continuation"

KNOWN_TYPES = frozenset(
    {WARCINFO, RESPONSE, REVISIT, METADATA, REQUEST, RESOURCE, CONVERSION, CONTINUATION}
)

# Revisit profiles defined by WARC 1.0/1.1.
PROFILE_IDENTICAL_PAYLOAD_DIGEST = (
    "http://netpreserve.org/warc/1.0/revisit/identical-payload-digest"
)
PROFILE_SERVER_NOT_MODIFIED = (
    "http://netpreserve.org/warc/1.0/revisit/server-not-modified"
)
PROFILE_IDENTICAL_PAYLOAD_DIGEST_1_1 = (
    "http://netpreserve.org/warc/1.1/revisit/identical-payload-digest"
)
PROFILE_SERVER_NOT_MODIFIED_1_1 = (
    "http://netpreserve.org/warc/1.1/revisit/server-not-modified"
)

IDENTICAL_PAYLOAD_PROFILES = frozenset(
    {PROFILE_IDENTICAL_PAYLOAD_DIGEST, PROFILE_IDENTICAL_PAYLOAD_DIGEST_1_1}
)
SERVER_NOT_MODIFIED_PROFILES = frozenset(
    {PROFILE_SERVER_NOT_MODIFIED, PROFILE_SERVER_NOT_MODIFIED_1_1}
)


class Headers:
    """A case-insensitive, order-preserving multi-map of byte headers.

    Header names are compared case-insensitively; repeated headers are kept
    (``get_all``) while :meth:`get` returns the last occurrence, matching the
    semantics used for HTTP fields.
    """

    def __init__(self, pairs: list[tuple[bytes, bytes]] | None = None) -> None:
        self._pairs: list[tuple[bytes, bytes]] = list(pairs or [])

    def add(self, name: bytes, value: bytes) -> None:
        self._pairs.append((name, value))

    def get(self, name: str | bytes, default: bytes | None = None) -> bytes | None:
        if isinstance(name, str):
            name = name.encode("ascii")
        wanted = name.lower()
        for k, v in reversed(self._pairs):
            if k.lower() == wanted:
                return v
        return default

    def get_all(self, name: str | bytes) -> list[bytes]:
        if isinstance(name, str):
            name = name.encode("ascii")
        wanted = name.lower()
        return [v for k, v in self._pairs if k.lower() == wanted]

    def pairs(self) -> list[tuple[bytes, bytes]]:
        return list(self._pairs)

    def items(self) -> Iterator[tuple[bytes, bytes]]:
        return iter(self._pairs)

    def __contains__(self, name: str | bytes) -> bool:
        return self.get(name) is not None

    def __len__(self) -> int:
        return len(self._pairs)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Headers) and other._pairs == self._pairs

    def __repr__(self) -> str:
        return f"Headers({self._pairs!r})"


# ---------------------------------------------------------------------------
# Low-level streaming parser events
# ---------------------------------------------------------------------------

@dataclass
class RecordBegin:
    """Emitted when a WARC record header block has been fully parsed."""

    offset: int
    length: int | None  # declared Content-Length; payload occupies this many bytes
    record_type: str
    warc_headers: Headers
    raw_header: bytes
    warnings: list[str] = field(default_factory=list)


@dataclass
class PayloadData:
    """A chunk of the record block (payload), in file order."""

    data: bytes


@dataclass
class RecordEnd:
    """Emitted after the full record block and following separator."""

    offset: int
    length: int  # bytes from version line through end of block (no separator)
    truncated: bool = False
    trunc_reason: str | None = None
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Query results
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RecordView:
    """An indexed record, as returned by the query entry points.

    It carries only metadata plus the on-disk location of the record
    (``file_path``/``offset``/``length``); bodies are never loaded until a
    caller explicitly resolves the record.
    """

    record_id: str
    record_type: str
    target_uri: str | None
    date: str | None
    epoch: float | None
    payload_digest: str | None
    payload_digest_algorithm: str | None
    refers_to: str | None
    revisit_profile: str | None
    http_status: int | None
    file_path: str
    offset: int
    length: int
    truncated: bool
    trunc_reason: str | None
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "record_type": self.record_type,
            "target_uri": self.target_uri,
            "date": self.date,
            "payload_digest": self.payload_digest,
            "payload_digest_algorithm": self.payload_digest_algorithm,
            "refers_to": self.refers_to,
            "revisit_profile": self.revisit_profile,
            "http_status": self.http_status,
            "file_path": self.file_path,
            "offset": self.offset,
            "length": self.length,
            "truncated": self.truncated,
            "trunc_reason": self.trunc_reason,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class RawRecordInfo:
    """A record produced by the low-level :func:`warcindex.reader.iter_records`.

    Unlike :class:`RecordView` it also carries the payload digest computed
    while streaming the block, regardless of any declared digest.
    """

    record_id: str
    record_type: str
    target_uri: str | None
    date: str | None
    epoch: float | None
    declared_payload_digest: str | None
    declared_payload_digest_algorithm: str | None
    computed_payload_digest: str
    computed_payload_digest_algorithm: str
    refers_to: str | None
    revisit_profile: str | None
    warc_headers: Headers
    http_status: int | None
    offset: int
    length: int
    truncated: bool
    trunc_reason: str | None
    warnings: tuple[str, ...]
