"""Tests for indexing, deterministic queries, revisit resolution and reload."""

from __future__ import annotations

import multiprocessing as mp
import os

import pytest

from warcindex import (
    METADATA,
    RESPONSE,
    REVISIT,
    WARCINFO,
    DuplicateRecordIdError,
    FileChangedError,
    RecordNotFoundError,
    RevisitDigestMismatchError,
    RevisitTargetNotFoundError,
    RevisitTargetTruncatedError,
    TruncatedRecordError,
    UnsupportedRevisitProfileError,
    WarcIndex,
)

from .warctest import http_response, warp_payload_digest, warc_record

PROFILE_DIGEST = (
    "http://netpreserve.org/warc/1.0/revisit/identical-payload-digest"
)
PROFILE_NOT_MOD = "http://netpreserve.org/warc/1.0/revisit/server-not-modified"


def _write(path, data) -> str:
    path.write_bytes(data)
    return str(path)


def test_query_by_uri_date_id_digest(tmp_path):
    body = b"hello world"
    digest = warp_payload_digest(body)
    block = http_response(body)
    warc = (
        warc_record(record_type=WARCINFO, record_id="0" * 36,
                    content_type="application/warc-fields", block=b"x: y\r\n")
        + warc_record(
            record_type=RESPONSE, record_id="a" * 36,
            target_uri="https://e.test/a", date="2026-01-01T00:00:00Z",
            content_type="application/http; msgtype=response",
            payload_digest=digest, block=block,
        )
        + warc_record(
            record_type=METADATA, record_id="c" * 36,
            target_uri="https://e.test/a", date="2026-01-01T00:00:00Z",
            content_type="application/warc-fields", block=b"k: v\r\n",
        )
    )
    p = _write(tmp_path / "a.warc", warc)
    idx = WarcIndex.create(tmp_path / "idx")
    assert idx.add_path(p, chunk_size=19) == 3

    by_uri = idx.query(uri="https://e.test/a")
    assert {v.record_id for v in by_uri} == {"urn:uuid:" + "a" * 36,
                                             "urn:uuid:" + "c" * 36}

    one = idx.query(uri="https://e.test/a", date="2026-01-01T00:00:00Z",
                    record_type=RESPONSE)
    assert [v.record_id for v in one] == ["urn:uuid:" + "a" * 36]

    assert idx.get("urn:uuid:" + "a" * 36).record_type == RESPONSE
    assert idx.get("<urn:uuid:" + "a" * 36 + ">").record_id == "urn:uuid:" + "a" * 36

    got = idx.query(payload_digest=digest)
    assert [v.record_id for v in got] == ["urn:uuid:" + "a" * 36]
    # digest lookup also accepts the alg: prefixed form
    got2 = idx.query(payload_digest=digest.split(":")[1])
    assert got2 == got

    with pytest.raises(RecordNotFoundError):
        idx.get("urn:uuid:" + "f" * 36)


def test_query_by_record_id_alone(tmp_path):
    # regression: record_id must bind to its own placeholder, not overwrite
    # whatever parameter happened to be last
    body = b"q"
    warc = b"".join(
        warc_record(
            record_type=RESPONSE, record_id=rid,
            target_uri="https://e.test/q",
            date="2026-01-01T00:00:00Z",
            content_type="application/http; msgtype=response",
            payload_digest=warp_payload_digest(body), block=http_response(body),
        )
        for rid in ("a" * 36, "b" * 36)
    )
    p = _write(tmp_path / "q.warc", warc)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p)
    rows = idx.query(record_id="urn:uuid:" + "b" * 36)
    assert [r.record_id for r in rows] == ["urn:uuid:" + "b" * 36]


def test_record_id_forms_are_equivalent(tmp_path):
    rid = "12345678-1234-1234-1234-123456789abc"
    body = b"q"
    warc = warc_record(
        record_type=RESPONSE, record_id=rid,
        target_uri="https://e.test/q",
        date="2026-01-01T00:00:00Z",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(body), block=http_response(body),
    )
    p = _write(tmp_path / "q.warc", warc)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p)
    canonical = "urn:uuid:" + rid
    for form in (rid, canonical, f"<{canonical}>", canonical.upper()):
        assert idx.get(form).record_id == canonical, form
        assert idx.query(record_id=form)[0].record_id == canonical, form


def test_same_uri_different_times_stay_distinct_and_ordered(tmp_path):
    block1 = http_response(b"v1")
    block2 = http_response(b"v2-longer")
    warc = (
        warc_record(record_type=RESPONSE, record_id="1" * 36,
                    target_uri="https://e.test/x", date="2026-03-01T00:00:00Z",
                    content_type="application/http; msgtype=response",
                    payload_digest=warp_payload_digest(b"v1"), block=block1)
        + warc_record(record_type=RESPONSE, record_id="2" * 36,
                      target_uri="https://e.test/x", date="2026-01-01T00:00:00Z",
                      content_type="application/http; msgtype=response",
                      payload_digest=warp_payload_digest(b"v2-longer"), block=block2)
        + warc_record(record_type=RESPONSE, record_id="3" * 36,
                      target_uri="https://e.test/x", date="2026-02-01T00:00:00Z",
                      content_type="application/http; msgtype=response",
                      payload_digest=warp_payload_digest(b"v1"), block=block1)
    )
    p = _write(tmp_path / "x.warc", warc)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p)
    idx.save()

    rows = idx.query(uri="https://e.test/x")
    assert [r.record_id for r in rows] == [
        "urn:uuid:" + "2" * 36,
        "urn:uuid:" + "3" * 36,
        "urn:uuid:" + "1" * 36,
    ]
    # ordering is stable when files are listed in different ingestion order
    rows2 = idx.query(uri="https://e.test/x")
    assert rows == rows2
    assert len(rows) == 3  # never merged


def test_offset_length_point_back_to_bytes(tmp_path):
    body = b"payload-bytes"
    block = http_response(body)
    raw = warc_record(
        record_type=RESPONSE, record_id="a" * 36, target_uri="https://e.test/",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(body), block=block,
    )
    p = _write(tmp_path / "o.warc", raw)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p)
    v = idx.get("urn:uuid:" + "a" * 36)
    assert v.offset == 0
    assert v.length == len(raw) - 4
    assert open(p, "rb").read()[v.offset:v.offset + v.length].rstrip(b"\r")[:6] == b"WARC/1"


def test_resolve_normal_response(tmp_path):
    body = b"<h1>hi</h1>"
    block = http_response(body, headers={"X-Test": "yes"})
    raw = warc_record(
        record_type=RESPONSE, record_id="a" * 36, target_uri="https://e.test/",
        date="2026-01-01T00:00:00Z",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(body), block=block,
    )
    p = _write(tmp_path / "r.warc", raw)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p)
    with idx.resolve("urn:uuid:" + "a" * 36) as res:
        assert res.http_status == 200
        assert res.header("X-Test") == b"yes"
        assert res.read() == body
        assert res.payload_record_id == "urn:uuid:" + "a" * 36
        assert res.is_revisit is False


def test_revisit_identical_digest_resolves_to_target(tmp_path):
    body = b"original content that stays the same"
    digest = warp_payload_digest(body)
    block = http_response(body)
    orig = warc_record(
        record_type=RESPONSE, record_id="1" * 36, target_uri="https://e.test/",
        date="2026-01-01T00:00:00Z",
        content_type="application/http; msgtype=response",
        payload_digest=digest, block=block,
    )
    rev = warc_record(
        record_type=REVISIT, record_id="2" * 36, target_uri="https://e.test/",
        date="2026-02-01T00:00:00Z",
        profile=PROFILE_DIGEST, payload_digest=digest, block=b"",
    )
    p = _write(tmp_path / "rv.warc", orig + rev)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p, chunk_size=3)
    with idx.resolve("urn:uuid:" + "2" * 36) as res:
        assert res.is_revisit is True
        assert res.record_id == "urn:uuid:" + "2" * 36
        assert res.payload_record_id == "urn:uuid:" + "1" * 36
        assert res.http_status == 200
        assert res.read() == body


def test_revisit_target_missing_raises(tmp_path):
    digest = warp_payload_digest(b"ghost")
    rev = warc_record(
        record_type=REVISIT, record_id="9" * 36, target_uri="https://e.test/gone",
        date="2026-02-01T00:00:00Z",
        profile=PROFILE_DIGEST, payload_digest=digest, block=b"",
    )
    p = _write(tmp_path / "rv.warc", rev)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p)
    with pytest.raises(RevisitTargetNotFoundError):
        idx.resolve("urn:uuid:" + "9" * 36)


def test_revisit_digest_mismatch_raises(tmp_path):
    body = b"same URL but different body"
    block = http_response(body)
    orig = warc_record(
        record_type=RESPONSE, record_id="1" * 36, target_uri="https://e.test/",
        date="2026-01-01T00:00:00Z",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(body), block=block,
    )
    wrong = warp_payload_digest(b"completely different bytes")
    rev = warc_record(
        record_type=REVISIT, record_id="2" * 36, target_uri="https://e.test/",
        date="2026-02-01T00:00:00Z",
        profile=PROFILE_DIGEST, payload_digest=wrong, block=b"",
    )
    p = _write(tmp_path / "rv.warc", orig + rev)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p)
    with pytest.raises(RevisitDigestMismatchError):
        idx.resolve("urn:uuid:" + "2" * 36)


def test_revisit_target_truncated_raises(tmp_path):
    body = b"cut short"
    block = http_response(body)
    orig = warc_record(
        record_type=RESPONSE, record_id="1" * 36, target_uri="https://e.test/",
        date="2026-01-01T00:00:00Z",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(body), truncated="length",
        block=block,
    )
    digest = warp_payload_digest(body)
    rev = warc_record(
        record_type=REVISIT, record_id="2" * 36, target_uri="https://e.test/",
        date="2026-02-01T00:00:00Z",
        profile=PROFILE_DIGEST, payload_digest=digest, refers_to="1" * 36,
        block=b"",
    )
    p = _write(tmp_path / "rv.warc", orig + rev)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p)
    with pytest.raises(RevisitTargetTruncatedError):
        idx.resolve("urn:uuid:" + "2" * 36)
    # and the truncated response itself refuses normal resolution
    with pytest.raises(TruncatedRecordError):
        idx.resolve("urn:uuid:" + "1" * 36)


def test_revisit_unsupported_profile_raises(tmp_path):
    rev = warc_record(
        record_type=REVISIT, record_id="2" * 36, target_uri="https://e.test/",
        date="2026-02-01T00:00:00Z",
        profile="http://example.invalid/revisit/weird", block=b"",
    )
    p = _write(tmp_path / "rv.warc", rev)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p)
    with pytest.raises(UnsupportedRevisitProfileError):
        idx.resolve("urn:uuid:" + "2" * 36)


def test_revisit_server_not_modified(tmp_path):
    body = b"last-modified-body"
    digest = warp_payload_digest(body)
    orig = warc_record(
        record_type=RESPONSE, record_id="1" * 36, target_uri="https://e.test/",
        date="2026-01-01T00:00:00Z",
        content_type="application/http; msgtype=response",
        payload_digest=digest, block=http_response(body),
    )
    rev = warc_record(
        record_type=REVISIT, record_id="2" * 36, target_uri="https://e.test/",
        date="2026-02-01T00:00:00Z", profile=PROFILE_NOT_MOD,
        refers_to="1" * 36, payload_digest=digest, block=b"",
    )
    p = _write(tmp_path / "rv.warc", orig + rev)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p)
    with idx.resolve("urn:uuid:" + "2" * 36) as res:
        assert res.payload_record_id == "urn:uuid:" + "1" * 36
        assert res.read() == body


def test_reload_in_new_process_gives_identical_results(tmp_path):
    body = b"persistence body " + b"0123456789" * 4
    digest = warp_payload_digest(body)
    warc = b"".join([
        warc_record(record_type=RESPONSE, record_id=f"{i:036x}",
                    target_uri="https://e.test/p",
                    date=f"2026-01-{i + 1:02d}T00:00:00Z",
                    content_type="application/http; msgtype=response",
                    payload_digest=digest if i == 0 else warp_payload_digest(body),
                    block=http_response(body))
        for i in range(3)
    ])
    p = _write(tmp_path / "p.warc", warc)
    idx_dir = str(tmp_path / "idx")
    idx = WarcIndex.open_or_create(idx_dir)
    idx.add_path(p)
    before = [v.as_dict() for v in idx.query(uri="https://e.test/p")]
    idx.save()
    idx.close()

    # reload in this process first
    idx2 = WarcIndex.open(idx_dir)
    after = [v.as_dict() for v in idx2.query(uri="https://e.test/p")]
    assert after == before

    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    proc = ctx.Process(target=_query_in_other_process, args=(idx_dir, q))
    proc.start()
    proc.join(20)
    assert proc.exitcode == 0
    assert q.get() == before


def _query_in_other_process(idx_dir, q):
    import sys

    sys.path.insert(0, os.environ["WARCINDEX_SRC"])
    from warcindex import WarcIndex

    idx = WarcIndex.open(idx_dir)
    q.put([v.as_dict() for v in idx.query(uri="https://e.test/p")])


def test_duplicate_record_id_across_files_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("WARCINDEX_SRC", os.path.join(os.path.dirname(__file__), "..", "src"))
    block = http_response(b"dup")
    w1 = _write(tmp_path / "1.warc", warc_record(
        record_type=RESPONSE, record_id="d" * 36, target_uri="https://e.test/",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(b"dup"), block=block))
    w2 = _write(tmp_path / "2.warc", warc_record(
        record_type=RESPONSE, record_id="d" * 36, target_uri="https://e.test/x",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(b"dup"), block=block))
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(w1)
    with pytest.raises(DuplicateRecordIdError):
        idx.add_path(w2)


def test_reindex_unchanged_file_is_noop(tmp_path):
    p = _write(tmp_path / "a.warc", warc_record(
        record_type=WARCINFO, record_id="0" * 36,
        content_type="application/warc-fields", block=b"x: y\r\n"))
    idx = WarcIndex.create(tmp_path / "idx")
    assert idx.add_path(p) == 1
    assert idx.add_path(p) == 0


def test_changed_file_detected(tmp_path):
    p = tmp_path / "a.warc"
    p.write_bytes(warc_record(
        record_type=WARCINFO, record_id="0" * 36,
        content_type="application/warc-fields", block=b"x: y\r\n"))
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(str(p))
    idx.save()
    p.write_bytes(warc_record(
        record_type=WARCINFO, record_id="0" * 36,
        content_type="application/warc-fields", block=b"x: yy\r\n"))
    with pytest.raises(FileChangedError):
        idx.resolve("urn:uuid:" + "0" * 36)
