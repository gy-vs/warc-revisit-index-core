"""Random-access retrieval of record blocks from original WARC files.

The index only stores coordinates (offset, length, ...).  When a replay asks
for a payload, this module re-opens the referenced file, seeks, and streams
the bytes back.  Both plain WARCs and per-record gzip WARCs are supported,
always with bounded buffers.
"""

from __future__ import annotations

import os
import zlib
from typing import Iterator, Protocol

from .errors import (
    GzipFormatError,
    SourceNotFoundError,
    StorageError,
    TruncatedRecordError,
)
from .httpmsg import DechunkError, Dechunker
from .model import RecordHandle

_CHUNK = 1 << 20  # 1 MiB streaming granularity


class RandomSource(Protocol):
    """Anything that can hand out raw record bytes by offset/length."""

    def read_range(self, offset: int, length: int) -> bytes: ...

    def iter_range(self, offset: int, length: int) -> Iterator[bytes]: ...


class FileSource:
    """A plain or per-record gzip WARC file on disk."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = os.fspath(path)
        if not os.path.isfile(self.path):
            raise SourceNotFoundError(self.path)

    @property
    def size(self) -> int:
        return os.path.getsize(self.path)

    def read_range(self, offset: int, length: int) -> bytes:
        return b"".join(self.iter_range(offset, length))

    def iter_range(self, offset: int, length: int) -> Iterator[bytes]:
        with open(self.path, "rb") as fh:
            fh.seek(offset)
            remaining = length
            while remaining > 0:
                chunk = fh.read(min(_CHUNK, remaining))
                if not chunk:
                    raise TruncatedRecordError(
                        f"{self.path}: short read at offset {offset} "
                        f"(wanted {length} bytes, hit EOF)"
                    )
                remaining -= len(chunk)
                yield chunk


def iter_block(
    handle: RecordHandle, source: RandomSource
) -> Iterator[bytes]:
    """Yield the raw WARC record block (uncompressed) in bounded chunks."""
    if handle.compressed_offset is not None:
        yield from _iter_gzip_block(handle, source)
        return
    start = handle.offset + handle.head_length
    yield from source.iter_range(start, handle.block_length)


def _iter_gzip_block(
    handle: RecordHandle, source: RandomSource
) -> Iterator[bytes]:
    assert handle.compressed_offset is not None
    assert handle.compressed_length is not None
    d = zlib.decompressobj(wbits=31)
    # Decompressed coordinates are relative to the start of this gzip
    # member.  The record starts at (record_offset - member_base) inside
    # the member; its block starts after the WARC header.
    member_base = (
        handle.member_logical_offset
        if handle.member_logical_offset is not None
        else handle.offset
    )
    record_start_in_member = handle.offset - member_base
    to_skip = record_start_in_member + handle.head_length
    wanted = handle.block_length
    emitted = 0
    decompressed_total = 0

    for compressed in source.iter_range(
        handle.compressed_offset, handle.compressed_length
    ):
        try:
            raw = d.decompress(compressed)
        except zlib.error as exc:
            raise GzipFormatError(f"gzip decompression failed: {exc}") from exc
        if raw:
            pos = 0
            if decompressed_total < to_skip:
                pos = min(len(raw), to_skip - decompressed_total)
            if pos < len(raw) and emitted < wanted:
                piece = raw[pos : pos + (wanted - emitted)]
                emitted += len(piece)
                yield piece
            decompressed_total += len(raw)
        if d.eof:
            try:
                tail = d.flush()
            except zlib.error as exc:
                raise GzipFormatError(f"gzip member CRC error: {exc}") from exc
            if tail:
                if decompressed_total >= to_skip and emitted < wanted:
                    piece = tail[: wanted - emitted]
                    emitted += len(piece)
                    yield piece
                decompressed_total += len(tail)
            break

    if emitted < wanted:
        raise TruncatedRecordError(
            f"gzip member at offset {handle.compressed_offset} yielded "
            f"{emitted} payload bytes, wanted {wanted}"
        )


def iter_payload(
    handle: RecordHandle, source: RandomSource
) -> Iterator[bytes]:
    """Yield the replay payload (HTTP body de-chunked when needed).

    For response/revisit this skips the HTTP status line and headers.  For
    every other record type the whole block is the payload.
    """
    if handle.record_type.value not in ("response", "revisit"):
        yield from iter_block(handle, source)
        return

    skipped = 0
    dechunker: Dechunker | None = Dechunker() if handle.http_chunked else None
    for chunk in iter_block(handle, source):
        if skipped < handle.payload_offset:
            take = min(len(chunk), handle.payload_offset - skipped)
            chunk = chunk[take:]
            skipped += take
        if not chunk:
            continue
        if dechunker is not None:
            try:
                for piece in dechunker.feed(chunk):
                    yield piece
            except DechunkError as exc:
                raise StorageError(f"invalid chunked encoding: {exc}") from exc
        else:
            yield chunk
    if dechunker is not None:
        try:
            dechunker.eof()
        except DechunkError as exc:
            raise StorageError(f"invalid chunked encoding: {exc}") from exc


def read_payload(handle: RecordHandle, source: RandomSource) -> bytes:
    """Convenience helper; prefer :func:`iter_payload` for large bodies."""
    return b"".join(iter_payload(handle, source))
