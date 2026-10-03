"""Tests for the validation entry point."""

from __future__ import annotations

import pytest

from warcindex import (
    RESPONSE,
    REVISIT,
    WARCINFO,
    WarcIndex,
    validate_index,
)

from .warctest import http_response, warp_payload_digest, warc_record

PROFILE_DIGEST = (
    "http://netpreserve.org/warc/1.0/revisit/identical-payload-digest"
)


def test_clean_index_validates(tmp_path):
    body = b"clean body content"
    warc = warc_record(
        record_type=RESPONSE, record_id="a" * 36, target_uri="https://e.test/",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(body), block=http_response(body),
    )
    p = str(tmp_path / "a.warc")
    open(p, "wb").write(warc)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p)
    report = validate_index(idx)
    assert report.ok
    assert report.errors == []
    assert len(report.warnings) == 0


def test_truncated_record_is_warning(tmp_path):
    body = b"short"
    warc = warc_record(
        record_type=RESPONSE, record_id="a" * 36, target_uri="https://e.test/",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(body), truncated="length",
        block=http_response(body),
    )
    p = str(tmp_path / "a.warc")
    open(p, "wb").write(warc)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p)
    report = validate_index(idx)
    assert report.ok  # truncation is a warning, not an error
    codes = {i.code for i in report.warnings}
    assert "truncated" in codes


def test_broken_digest_on_disk_is_error(tmp_path):
    body = b"original"
    warc = warc_record(
        record_type=RESPONSE, record_id="a" * 36, target_uri="https://e.test/",
        content_type="application/http; msgtype=response",
        payload_digest=warp_payload_digest(body), block=http_response(body),
    )
    p = tmp_path / "a.warc"
    p.write_bytes(warc)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(str(p))
    # corrupt a body byte inside the HTTP payload region
    blob = bytearray(p.read_bytes())
    idx_payload = blob.find(b"original")
    blob[idx_payload] = ord(b"X")
    p.write_bytes(blob)
    # keep file size identical: size check passes, digest check must fire
    idx2 = WarcIndex.open(str(tmp_path / "idx"))
    report = validate_index(idx2)
    assert not report.ok
    assert any(i.code == "digest-mismatch" for i in report.errors)


def test_revisit_missing_target_is_error(tmp_path):
    rev = warc_record(
        record_type=REVISIT, record_id="r" * 36, target_uri="https://e.test/x",
        date="2026-02-01T00:00:00Z", profile=PROFILE_DIGEST,
        payload_digest=warp_payload_digest(b"x"), block=b"",
    )
    p = str(tmp_path / "r.warc")
    open(p, "wb").write(rev)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p)
    report = validate_index(idx)
    assert not report.ok
    assert any(i.code == "revisit-target-missing" for i in report.errors)


def test_raise_on_error_mode(tmp_path):
    rev = warc_record(
        record_type=REVISIT, record_id="r" * 36, target_uri="https://e.test/x",
        date="2026-02-01T00:00:00Z", profile=PROFILE_DIGEST,
        payload_digest=warp_payload_digest(b"x"), block=b"",
    )
    p = str(tmp_path / "r.warc")
    open(p, "wb").write(rev)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p)
    with pytest.raises(Exception):
        validate_index(idx, raise_on_error=True)


def test_warcinfo_validates(tmp_path):
    warc = warc_record(
        record_type=WARCINFO, record_id="w" * 36,
        content_type="application/warc-fields", block=b"software: x\r\n",
    )
    p = str(tmp_path / "w.warc")
    open(p, "wb").write(warc)
    idx = WarcIndex.create(tmp_path / "idx")
    idx.add_path(p)
    report = validate_index(idx)
    assert report.ok
