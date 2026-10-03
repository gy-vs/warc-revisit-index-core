"""High-level convenience entry points: read WARC bytes into an index."""

from __future__ import annotations

import os
from typing import BinaryIO, Iterable

from .index import Index, RecordView
from .parser import RecordFeeder
from .model import RecordHandle


def read_file(
    index: Index,
    path: str | os.PathLike[str],
    compression: str = "auto",
    chunk_size: int = 1 << 20,
) -> list[RecordView]:
    """Index a WARC file from disk (streaming, constant memory)."""
    return index.add_source(path, compression=compression, chunk_size=chunk_size)


def read_stream(
    index: Index,
    stream: BinaryIO | Iterable[bytes],
    source_path: str = "<stream>",
    compression: str = "auto",
    chunk_size: int = 1 << 20,
    file_size: int | None = None,
) -> list[RecordView]:
    """Index WARC bytes from a binary stream or any chunk iterable."""

    def _chunks() -> Iterable[bytes]:
        if hasattr(stream, "read"):
            while True:
                chunk = stream.read(chunk_size)
                if not chunk:
                    return
                yield chunk
        else:
            yield from stream  # type: ignore[union-attr]

    return index.add_stream(
        _chunks(),
        source_path=source_path,
        compression=compression,
        file_size=file_size,
    )


def parse_bytes(data: bytes, compression: str = "auto") -> list[RecordHandle]:
    """Parse a complete WARC byte string without indexing it.

    Mainly useful for tests and one-off inspection.
    """
    feeder = RecordFeeder(compression=compression)
    records = feeder.feed(data)
    records.extend(feeder.finish())
    return records
