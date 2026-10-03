"""Tests for the chunk-independent streaming parser and reader layer."""

from __future__ import annotations

import io

import pytest

from warcindex import (
    METADATA,
    RESPONSE,
    REVISIT,
    WARCINFO,
    WarcHeaderError,
    WarcStreamParser,
    WarcVersionError,
    iter_records,
)
from warcindex.models import PayloadData, RecordBegin, RecordEnd

from .warctest import (
    b32_digest,
    http_response,
    warp_payload_digest,
    warc_record,
)


def _parse_all(data: bytes, chunk: int):
    p = WarcStreamParser()
    events = []
    for i in range(0, len(data), chunk):
        events.extend(p.feed(data[i:i + chunk]))
    events.extend(p.feed_eof())
    return events


@pytest.mark.parametrize("chunk", [1, 2, 3, 7, 64, 4096])
def test_chunk_splitting_is_invisible(chunk):
    body = b"<html><body>hello</body></html>"
    block = http_response(body)
    rec = warc_record(
        record_type=RESPONSE,
        record_id="11111111-1111-1111-1111-111111111111",
        target_uri="https://example.com/a",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(body),
        block=block,
    )
    events = _parse_all(rec, chunk)
    begins = [e for e in events if isinstance(e, RecordBegin)]
    ends = [e for e in events if isinstance(e, RecordEnd)]
    payloads = [e for e in events if isinstance(e, PayloadData)]
    assert len(begins) == 1
    assert len(ends) == 1
    assert begins[0].offset == 0
    assert begins[0].length == len(block)
    assert b"".join(p.data for p in payloads) == block
    assert ends[0].length == len(rec) - 4  # without trailing CRLFCRLF


def test_two_records_same_uri_are_distinct():
    body = b"x"
    block = http_response(body)
    r1 = warc_record(
        record_type=RESPONSE, record_id="a" * 36,
        target_uri="https://example.com/", date="2026-01-01T00:00:00Z",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(body), block=block,
    )
    r2 = warc_record(
        record_type=RESPONSE, record_id="b" * 36,
        target_uri="https://example.com/", date="2026-02-01T00:00:00Z",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(body), block=block,
    )
    events = _parse_all(r1 + r2, 5)
    begins = [e for e in events if isinstance(e, RecordBegin)]
    ends = [e for e in events if isinstance(e, RecordEnd)]
    assert [b.offset for b in begins] == [0, len(r1)]
    assert len(ends) == 2


def test_all_required_record_types_recognised(tmp_path):
    body = b"hello"
    block = http_response(body)
    digest = warp_payload_digest(body)
    blob = b"".join([
        warc_record(record_type=WARCINFO, record_id="0" * 36,
                    content_type="application/warc-fields", block=b"software: test\r\n"),
        warc_record(record_type=RESPONSE, record_id="1" * 36,
                    target_uri="https://e.test/",
                    content_type="application/http; msgtype=response",
                    payload_digest=digest, block=block),
        warc_record(record_type=REVISIT, record_id="2" * 36,
                    target_uri="https://e.test/",
                    refers_to="1" * 36,
                    profile="http://netpreserve.org/warc/1.0/revisit/identical-payload-digest",
                    payload_digest=digest, block=b""),
        warc_record(record_type=METADATA, record_id="3" * 36,
                    target_uri="https://e.test/",
                    content_type="application/warc-fields",
                    block=b"via: test\r\n"),
    ])
    path = tmp_path / "mix.warc"
    path.write_bytes(blob)
    infos = list(iter_records(path, chunk_size=13))
    assert [i.record_type for i in infos] == [WARCINFO, RESPONSE, REVISIT, METADATA]


def test_bad_version_line_raises():
    bad = b"NOTWARC/1.0\r\nX: y\r\n\r\n\r\n"
    with pytest.raises(WarcVersionError):
        _parse_all(bad, 4)


def test_missing_content_length_raises():
    rec = (
        b"WARC/1.0\r\n"
        b"WARC-Type: response\r\n"
        b"WARC-Record-ID: <urn:uuid:" + b"4" * 36 + b">\r\n"
        b"\r\nbody\r\n\r\n"
    )
    with pytest.raises(WarcHeaderError):
        _parse_all(rec, 3)


def test_eof_truncated_record_is_flagged():
    body = b"x" * 100
    block = http_response(body)
    rec = warc_record(
        record_type=RESPONSE, record_id="5" * 36,
        target_uri="https://e.test/x",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(body), block=block,
        no_separator=True,
    )
    # cut the block short
    cut = rec[: len(rec) - 30]
    events = _parse_all(cut, 11)
    end = [e for e in events if isinstance(e, RecordEnd)][0]
    assert end.truncated is True
    assert any("EOF" in w for w in end.warnings)


def test_warc_truncated_header_flag():
    rec = warc_record(
        record_type=RESPONSE, record_id="6" * 36,
        target_uri="https://e.test/x",
        content_type="application/http; msgtype=response",
        truncated="length", block=b"partial",
    )
    events = _parse_all(rec, 8)
    begin = [e for e in events if isinstance(e, RecordBegin)][0]
    end = [e for e in events if isinstance(e, RecordEnd)][0]
    assert end.truncated is True
    assert end.trunc_reason == "length"
    assert any("truncated" in w for w in begin.warnings)


def test_reader_computes_http_entity_digest(tmp_path):
    body = b"".join(bytes([i % 256]) for i in range(5000))
    block = http_response(body, chunked=True)
    rec = warc_record(
        record_type=RESPONSE, record_id="7" * 36,
        target_uri="https://e.test/chunked",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(body),
        block=block,
    )
    path = tmp_path / "c.warc"
    path.write_bytes(rec)
    infos = list(iter_records(path, chunk_size=1))  # extreme chunking
    info = infos[0]
    assert info.computed_payload_digest == b32_digest(body)
    assert info.computed_payload_digest == info.declared_payload_digest
    assert info.http_status == 200
    assert not info.truncated


def test_reader_warns_on_declared_digest_mismatch(tmp_path):
    block = http_response(b"actual body")
    rec = warc_record(
        record_type=RESPONSE, record_id="8" * 36,
        target_uri="https://e.test/",
        content_type="application/http; msgtype=response",
        payload_digest="sha1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        block=block,
    )
    path = tmp_path / "m.warc"
    path.write_bytes(rec)
    info = list(iter_records(path))[0]
    assert info.computed_payload_digest != info.declared_payload_digest


def test_reader_accepts_filelike_stream():
    block = http_response(b"abc")
    rec = warc_record(
        record_type=RESPONSE, record_id="9" * 36,
        target_uri="http://e.test/",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(b"abc"), block=block,
    )
    infos = list(iter_records(io.BytesIO(rec), chunk_size=7))
    assert len(infos) == 1
    assert infos[0].offset == 0
    assert infos[0].length == len(rec) - 4


def test_offsets_of_three_records_are_exact():
    blocks = [
        (WARCINFO, b"software: x\r\n", "application/warc-fields", None),
        (RESPONSE, http_response(b"one"), "application/http; msgtype=response",
         warp_payload_digest(b"one")),
        (METADATA, b"k: v\r\n", "application/warc-fields", None),
    ]
    rids = ["1" * 36, "2" * 36, "3" * 36]
    blob = b""
    boundaries = []
    for (rtype, blk, ctype, digest), rid in zip(blocks, rids):
        boundaries.append(len(blob))
        kwargs = dict(
            record_type=rtype, record_id=rid,
            content_type=ctype, block=blk,
        )
        if rtype == RESPONSE:
            kwargs["target_uri"] = "https://e.test/"
            kwargs["payload_digest"] = digest
        blob += warc_record(**kwargs)
    infos = list(iter_records(io.BytesIO(blob), chunk_size=2))
    assert [i.offset for i in infos] == boundaries
    for info in infos:
        assert blob[info.offset:info.offset + 8] == b"WARC/1.0"
    assert infos[-1].offset + infos[-1].length + 4 == len(blob)


def test_bare_lf_produces_warning():
    rec = warc_record(
        record_type=WARCINFO, record_id="a" * 36,
        content_type="application/warc-fields", block=b"x: y\r\n",
        bare_lf=True,
    )
    events = _parse_all(rec, 5)
    end = [e for e in events if isinstance(e, RecordEnd)][0]
    assert any("bare LF" in w for w in end.warnings)
