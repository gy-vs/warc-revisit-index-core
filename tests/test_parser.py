import pytest

from warcarchive.model import (
    RecordType,
    W_MISSING_TERMINATOR,
    W_RECORD_TRUNCATED,
)
from warcarchive.parser import RecordFeeder
from warcarchive.errors import WarcFormatError, GzipFormatError

from warcmaker import (
    b32_digest,
    feed_in_chunks,
    gzip_records,
    http_response,
    warc_record,
    warcinfo,
)


def parse(data, compression="auto", chunk=4096):
    feeder = RecordFeeder(compression)
    out = []
    for i in range(0, len(data), chunk):
        out.extend(feeder.feed(data[i : i + chunk]))
    out.extend(feeder.finish())
    return out


def test_basic_record_types_and_fields():
    body = b"<html>hello</html>"
    resp_block = http_response(body)
    rec = warc_record(
        "response", resp_block,
        record_id="urn:uuid:r1", uri="https://example.com/",
        payload_digest=b32_digest(body),
    )
    records = parse(rec)
    assert len(records) == 1
    h = records[0]
    assert h.record_type is RecordType.RESPONSE
    assert h.record_id == "urn:uuid:r1"
    assert h.target_uri == "https://example.com/"
    assert h.http_status == 200
    assert h.http_head.endswith(b"\r\n\r\n")
    assert h.payload_offset == len(h.http_head)
    assert h.block_length == len(resp_block)
    assert h.length == h.head_length + h.block_length + 4
    assert h.payload_digest == b32_digest(body)


def test_warcinfo_metadata_recognized():
    data = warcinfo() + warc_record("metadata", b"x: y\r\n",
                                    record_id="urn:uuid:m1")
    types = [r.record_type for r in parse(data)]
    assert types == [RecordType.WARCINFO, RecordType.METADATA]


def test_two_captures_same_uri_are_distinct_sorted_by_date():
    body1, body2 = b"v1", b"version-two"
    blocks = [
        warc_record("response", http_response(body1),
                    record_id="urn:uuid:a",
                    uri="https://example.com/",
                    date="2026-03-01T00:00:00Z",
                    payload_digest=b32_digest(body1)),
        warc_record("response", http_response(body2),
                    record_id="urn:uuid:b",
                    uri="https://example.com/",
                    date="2026-01-01T00:00:00Z",
                    payload_digest=b32_digest(body2)),
    ]
    records = parse(b"".join(reversed(blocks)))
    # Parser order = file order.
    assert [r.record_id for r in records] == ["urn:uuid:b", "urn:uuid:a"]
    dates = [r.date for r in records]
    assert dates[0] < dates[1]


def test_arbitrary_chunk_sizes_give_same_result():
    body = b"abc" * 1000
    data = warc_record("response", http_response(body),
                       record_id="urn:uuid:x",
                       uri="https://example.com/",
                       payload_digest=b32_digest(body))
    expected = parse(data, chunk=1 << 20)
    for sizes in ([1], [3], [7, 13, 64], [1, 1, 1, 100000]):
        feeder = RecordFeeder()
        got = feed_in_chunks(feeder, data, sizes)
        assert len(got) == len(expected)
        a, b = got[0], expected[0]
        assert a.offset == b.offset
        assert a.length == b.length
        assert a.head_length == b.head_length
        assert a.block_length == b.block_length
        assert a.payload_offset == b.payload_offset


def test_chunked_http_payload_offset_and_flag():
    body = b"chunked body content"
    block = http_response(body, chunked=True)
    rec = warc_record("response", block, record_id="urn:uuid:c",
                      uri="https://example.com/")
    h = parse(rec)[0]
    assert h.http_chunked is True
    assert h.payload_offset == len(h.http_head)
    # framed chunk bytes are longer than the decoded body
    assert h.block_length - h.payload_offset > len(body)


def test_truncated_record_by_short_block_warns():
    block = http_response(b"x" * 100)
    full = warc_record("response", block,
                       record_id="urn:uuid:t",
                       force_content_length=len(block) + 200)
    # Cut mid-block so the header is complete but the body ends early.
    cut = full.find(b"\r\n\r\n") + 4 + 50
    feeder = RecordFeeder("plain")
    feeder.feed(full[:cut])
    records = feeder.finish()
    assert W_RECORD_TRUNCATED in records[0].warnings
    assert records[0].block_length == 50


def test_missing_final_terminator_warns_but_parses():
    rec = warc_record("response", http_response(b"x"),
                      record_id="urn:uuid:z",
                      uri="https://example.com/")
    h = parse(rec[:-2])[0]
    assert W_MISSING_TERMINATOR in h.warnings


def test_bad_magic_raises_format_error():
    feeder = RecordFeeder("gzip")
    with pytest.raises(GzipFormatError):
        feeder.feed(b"not gzip at all")
        feeder.finish()


def test_missing_content_length_raises():
    rec = warc_record("metadata", b"data", omit_content_length=True)
    with pytest.raises(WarcFormatError):
        parse(rec)


def test_gzip_per_record_roundtrip():
    body1, body2 = b"first", b"second"
    recs = [
        warc_record("response", http_response(body1),
                    record_id="urn:uuid:g1",
                    uri="https://a.example/",
                    payload_digest=b32_digest(body1)),
        warc_record("response", http_response(body2),
                    record_id="urn:uuid:g2",
                    uri="https://b.example/",
                    payload_digest=b32_digest(body2)),
    ]
    data = gzip_records(recs)
    parsed = parse(data, chunk=37)  # awkward chunks inside gzip bytes
    assert [r.record_id for r in parsed] == ["urn:uuid:g1", "urn:uuid:g2"]
    for r in parsed:
        assert r.compressed_offset is not None
        assert r.compressed_length is not None
        assert r.gzip_crc_ok is True
    assert parsed[1].compressed_offset > parsed[0].compressed_offset


def test_crc_corruption_detected():
    body = b"corrupt me"
    data = bytearray(gzip_records([
        warc_record("response", http_response(body), record_id="urn:uuid:k")
    ]))
    # Flip a byte in the compressed payload (after the 10-byte gzip header).
    pos = min(40, len(data) // 2)
    data[pos] ^= 0xFF
    with pytest.raises(GzipFormatError):
        parse(bytes(data))
