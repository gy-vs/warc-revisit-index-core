"""Memory bounds, materialization and edge-case tests."""

from __future__ import annotations

import gc
import tracemalloc

from warcindex import (
    CompressionUnsupportedError,
    RESPONSE,
    WarcIndex,
    iter_records,
)

from .warctest import http_response, warp_payload_digest, warc_record


def test_iteration_memory_does_not_track_file_size(tmp_path):
    # ~20 MiB WARC; parser/reader retained memory must stay small.
    body = bytes((i * 7 + 3) % 256 for i in range(4096))
    block = http_response(body)
    rec = warc_record(
        record_type=RESPONSE, record_id="a" * 36, target_uri="https://e.test/big",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(body), block=block,
    )
    p = tmp_path / "big.warc"
    with open(p, "wb") as fh:
        for _ in range(200):
            fh.write(rec)

    gc.collect()
    tracemalloc.start()
    base = tracemalloc.take_snapshot()
    count = 0
    digest = None
    for info in iter_records(str(p), chunk_size=4096):
        count += 1
        digest = info.computed_payload_digest
    end = tracemalloc.take_snapshot()
    stats = end.compare_to(base, "lineno")
    growth = sum(s.size_diff for s in stats if s.size_diff > 0)
    tracemalloc.stop()

    assert count == 200
    assert digest == warp_payload_digest(body).split(":")[1]
    # Generous ceiling: small parser/index structures, but never file-sized.
    assert growth < 2 * 1024 * 1024, f"grew {growth} bytes"


def test_index_memory_does_not_track_file_size(tmp_path):
    body = bytes((i * 13 + 1) % 256 for i in range(8192))
    rec = warc_record(
        record_type=RESPONSE, record_id="1" * 36, target_uri="https://e.test/big",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(body), block=http_response(body),
    )
    p = tmp_path / "big.warc"
    for i in range(40):
        rid = f"{i + 1:036x}"
        with open(p, "ab") as fh:
            fh.write(warc_record(
                record_type=RESPONSE, record_id=rid,
                target_uri="https://e.test/big",
                date=f"2026-01-{(i % 27) + 1:02d}T00:00:00Z",
                content_type="application/http; msgtype=response",
                payload_digest=warp_payload_digest(body), block=http_response(body),
            ))

    gc.collect()
    tracemalloc.start()
    base = tracemalloc.take_snapshot()
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(str(p), chunk_size=4096)
    end = tracemalloc.take_snapshot()
    growth = sum(
        s.size_diff for s in end.compare_to(base, "lineno") if s.size_diff > 0
    )
    tracemalloc.stop()
    assert len(idx) == 40
    assert growth < 4 * 1024 * 1024


def test_gzip_input_rejected(tmp_path):
    p = tmp_path / "a.warc.gz"
    p.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 32)
    try:
        list(iter_records(str(p)))
        assert False, "expected CompressionUnsupportedError"
    except CompressionUnsupportedError:
        pass


def test_chunked_http_body_materializes_decoded(tmp_path):
    body = b"chunked-" * 100
    block = http_response(body, chunked=True)
    raw = warc_record(
        record_type=RESPONSE, record_id="a" * 36, target_uri="https://e.test/c",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(body), block=block,
    )
    p = str(tmp_path / "c.warc")
    open(p, "wb").write(raw)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p, chunk_size=1)
    with idx.resolve("urn:uuid:" + "a" * 36) as res:
        assert res.read() == body
        assert b"chunk-size" not in body


def test_query_order_total_and_deterministic(tmp_path):
    recs = b""
    for i in range(10):
        body = f"body-{i}".encode()
        recs += warc_record(
            record_type=RESPONSE, record_id=f"{i:036x}",
            target_uri=f"https://e.test/{i % 3}",
            date=f"2026-01-{(i % 27) + 1:02d}T00:00:00Z",
            content_type="application/http; msgtype=response",
            payload_digest=warp_payload_digest(body), block=http_response(body),
        )
    p = str(tmp_path / "d.warc")
    open(p, "wb").write(recs)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p)
    first = [(v.target_uri, v.date, v.record_id) for v in idx.query()]
    second = [(v.target_uri, v.date, v.record_id) for v in idx.query()]
    assert first == second
    assert first == sorted(first, key=lambda t: (t[0], t[1], t[2]))


def test_nonhttp_payload_returned_as_block(tmp_path):
    block = b"software: warcindex-tests\r\nformat: WARC File Format 1.0\r\n"
    raw = warc_record(
        record_type="warcinfo", record_id="w" * 36,
        content_type="application/warc-fields", block=block,
    )
    p = str(tmp_path / "w.warc")
    open(p, "wb").write(raw)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p)
    with idx.resolve("urn:uuid:" + "w" * 36) as res:
        assert res.is_http is False
        assert res.read() == block
        assert res.payload_record_id == "urn:uuid:" + "w" * 36


def test_warnings_carry_through_to_views(tmp_path):
    # declared digest mismatch becomes a stored warning
    raw = warc_record(
        record_type=RESPONSE, record_id="a" * 36, target_uri="https://e.test/",
        content_type="application/http; msgtype=response",
        payload_digest="sha1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        block=http_response(b"actual"),
    )
    p = str(tmp_path / "w.warc")
    open(p, "wb").write(raw)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p)
    view = idx.get("urn:uuid:" + "a" * 36)
    assert any("digest" in w for w in view.warnings)
