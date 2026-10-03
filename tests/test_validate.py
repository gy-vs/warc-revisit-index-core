import gzip
import os

import pytest

from warcarchive import (
    Index,
    validate,
)
from warcarchive.validate import (
    ISSUE_PAYLOAD_DIGEST_MISMATCH,
    ISSUE_RECORD_TRUNCATED,
    ISSUE_REVISIT_UNRESOLVABLE,
    ISSUE_SOURCE_MISSING,
    ISSUE_GZIP_TRUNCATED,
)
from warcarchive.storage import (
    FileSource,
    iter_payload,
    TruncatedRecordError,
    SourceNotFoundError,
)

from warcmaker import (
    PROFILE_IDENTICAL,
    b32_digest,
    gzip_records,
    http_response,
    warc_record,
)


def test_clean_archive_validates_ok(tmp_path):
    body = b"good body"
    rec = warc_record("response", http_response(body),
                      record_id="urn:uuid:ok",
                      uri="https://example.com/",
                      payload_digest=b32_digest(body))
    p = tmp_path / "ok.warc"
    p.write_bytes(rec)
    idx = Index.create(":memory:")
    idx.add_source(p)
    report = validate(idx, include_parse_warnings=False)
    assert report.ok
    assert report.checked == 1


def test_digest_corruption_is_reported(tmp_path):
    body = b"actual bytes"
    block = http_response(body)
    # Corrupt declared digest on purpose.
    rec = warc_record("response", block, record_id="urn:uuid:bad",
                      uri="https://example.com/",
                      payload_digest=b32_digest(b"different"))
    p = tmp_path / "bad.warc"
    p.write_bytes(rec)
    idx = Index.create(":memory:")
    idx.add_source(p)
    report = validate(idx, include_parse_warnings=False)
    codes = {i.code for i in report.issues}
    assert ISSUE_PAYLOAD_DIGEST_MISMATCH in codes


def test_unresolvable_revisit_is_reported_not_raised(tmp_path):
    block = http_response(b"", status=304)
    rec = warc_record(
        "revisit", block,
        record_id="urn:uuid:rev", uri="https://example.com/",
        date="2026-02-01T00:00:00Z",
        payload_digest=b32_digest(b"ghost"),
        extra_headers={"WARC-Profile": PROFILE_IDENTICAL},
    )
    p = tmp_path / "r.warc"
    p.write_bytes(rec)
    idx = Index.create(":memory:")
    idx.add_source(p)
    report = validate(idx, include_parse_warnings=False)
    assert any(i.code == ISSUE_REVISIT_UNRESOLVABLE for i in report.issues)


def test_truncated_gzip_member_reported(tmp_path):
    body = b"x" * 5000
    rec = warc_record("response", http_response(body),
                      record_id="urn:uuid:g")
    data = gzip.compress(rec)
    # Keep the gzip header, the complete WARC header and most of the body,
    # but cut the member before it ends.
    p = tmp_path / "t.warc.gz"
    p.write_bytes(data[: len(data) - 200])
    idx = Index.create(":memory:")
    idx.add_source(p)
    report = validate(idx, verify_payloads=False, include_parse_warnings=False)
    assert ISSUE_GZIP_TRUNCATED in {i.code for i in report.issues}


def test_warc_truncated_header_reported(tmp_path):
    body = b"x" * 100
    full = warc_record("response", http_response(body),
                       record_id="urn:uuid:t",
                       payload_digest=b32_digest(body),
                       truncated="length")
    p = tmp_path / "t.warc"
    p.write_bytes(full)
    idx = Index.create(":memory:")
    idx.add_source(p)
    report = validate(idx, include_parse_warnings=False)
    assert ISSUE_RECORD_TRUNCATED in {i.code for i in report.issues}


def test_missing_source_file_is_reported(tmp_path):
    body = b"persisted"
    p = tmp_path / "moved.warc"
    p.write_bytes(warc_record(
        "response", http_response(body), record_id="urn:uuid:m",
        uri="https://example.com/", payload_digest=b32_digest(body)))
    db = tmp_path / "idx.db"
    idx = Index.create(db)
    idx.add_source(p)
    idx.close()
    os.unlink(p)
    idx2 = Index.open(db)
    report = validate(idx2, include_parse_warnings=False)
    assert any(i.code == ISSUE_SOURCE_MISSING for i in report.issues)


def test_short_file_read_raises_truncated(tmp_path):
    body = b"abc" * 100
    p = tmp_path / "s.warc"
    p.write_bytes(warc_record(
        "response", http_response(body), record_id="urn:uuid:s",
        uri="https://example.com/", payload_digest=b32_digest(body)))
    idx = Index.create(":memory:")
    idx.add_source(p)
    # Truncate the backing file behind the index's back.
    size = os.path.getsize(p)
    with open(p, "r+b") as fh:
        fh.truncate(size - 20)
    # force an out-of-range read via raw FileSource coordinates
    with pytest.raises(TruncatedRecordError):
        FileSource(p).read_range(size - 30, 40)


def test_source_not_found_error_type(tmp_path):
    with pytest.raises(SourceNotFoundError):
        FileSource(tmp_path / "does-not-exist.warc")


def test_gzip_payload_offsets(tmp_path):
    body = b"gzip body content"
    data = gzip_records([warc_record(
        "response", http_response(body), record_id="urn:uuid:g",
        uri="https://example.com/")])
    p = tmp_path / "g.warc.gz"
    p.write_bytes(data)
    idx = Index.create(":memory:")
    view = idx.add_source(p)[0]
    assert view.payload_bytes() == body
    # iter_payload produces same bytes in small chunks
    chunks = list(iter_payload(view.handle, FileSource(p)))
    assert b"".join(chunks) == body
