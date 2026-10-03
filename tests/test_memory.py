"""Memory must stay flat as WARC file size grows.

We stream a sizable WARC (many large records) through both the parser and
the indexer and cap the *Python* allocation peak with tracemalloc.  The
relevant guarantee is that peak memory does not scale with file size.
"""

import gc
import os
import tracemalloc

from warcarchive import Index, Query
from warcarchive.parser import RecordFeeder

from warcmaker import b32_digest, http_response, warc_record


def _build_file(path, record_count, body_size):
    body = b"a" * body_size
    block = http_response(body)
    digest = b32_digest(body)
    with open(path, "wb") as fh:
        for i in range(record_count):
            fh.write(warc_record(
                "response", block,
                record_id=f"urn:uuid:big-{i:08d}",
                uri=f"https://example.com/page/{i % 50}",
                date=f"2026-01-{(i % 28) + 1:02d}T00:00:00Z",
                payload_digest=digest,
            ))


def test_parser_memory_is_bounded(tmp_path):
    path = tmp_path / "big.warc"
    _build_file(path, record_count=120, body_size=256 * 1024)  # ~30 MiB
    size = os.path.getsize(path)
    assert size > 25 * 1024 * 1024

    gc.collect()
    tracemalloc.start()
    try:
        feeder = RecordFeeder()
        count = 0
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(64 * 1024)  # deliberately small chunks
                if not chunk:
                    break
                count += len(feeder.feed(chunk))
        count += len(feeder.finish())
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert count == 120
    # Header prefix scan is capped at ~1 MiB; peak must be far below the
    # 30 MiB file size.
    assert peak < 8 * 1024 * 1024, peak


def test_indexer_memory_is_bounded(tmp_path):
    path = tmp_path / "big2.warc"
    _build_file(path, record_count=120, body_size=256 * 1024)

    gc.collect()
    tracemalloc.start()
    try:
        idx = Index.create(str(tmp_path / "big.db"))
        idx.add_source(path, chunk_size=128 * 1024)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert idx.count() == 120
    assert peak < 16 * 1024 * 1024, peak
    # Index is usable and every captured URI still resolves to bytes.
    pages = idx.query(Query(uri="https://example.com/page/0"))
    assert pages, "expected captures for page/0"
    assert pages[0].payload_bytes() == b"a" * (256 * 1024)
    idx.close()
