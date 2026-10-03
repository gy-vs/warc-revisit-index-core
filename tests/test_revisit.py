import pytest

from warcarchive import (
    DigestMismatchError,
    Index,
    PayloadResult,
    RevisitDigestMismatchError,
    RevisitProfileError,
    RevisitTargetNotFoundError,
    RevisitTruncatedError,
)

from warcmaker import (
    PROFILE_304,
    PROFILE_IDENTICAL,
    b32_digest,
    http_response,
    warc_record,
)


def build(tmp_path, records):
    p = tmp_path / "c.warc"
    p.write_bytes(b"".join(records))
    idx = Index.create(":memory:")
    idx.add_source(p)
    return idx, p


def response(rid, body, uri="https://example.com/", date="2026-01-01T00:00:00Z",
             digest=None, truncated=None, extra=None, status=200):
    return warc_record(
        "response", http_response(body, status=status),
        record_id=rid, uri=uri, date=date,
        payload_digest=digest or b32_digest(body),
        truncated=truncated, extra_headers=extra,
    )


def revisit(rid, date, uri="https://example.com/", digest=None,
            profile=PROFILE_IDENTICAL, refers_to=None, truncated=None,
            extra=None):
    headers = {"WARC-Profile": profile}
    if refers_to:
        headers["WARC-Refers-To"] = f"<{refers_to}>"
    if extra:
        headers.update(extra)
    block = http_response(b"", status=304)
    return warc_record(
        "revisit", block, record_id=rid, uri=uri, date=date,
        payload_digest=digest, extra_headers=headers, truncated=truncated,
    )


def test_revisit_resolves_via_payload_digest_profile(tmp_path):
    body = b"<html>original</html>"
    idx, _ = build(tmp_path, [
        response("urn:uuid:orig", body, date="2026-01-01T00:00:00Z"),
        revisit("urn:uuid:rev", "2026-02-01T00:00:00Z",
                digest=b32_digest(body)),
    ])
    view = idx.get_by_id("urn:uuid:rev")
    assert view.is_revisit
    result = view.resolve()
    assert isinstance(result, PayloadResult)
    assert result.body == body
    assert result.origin_record_id == "urn:uuid:orig"
    assert b"HTTP/1.1 200" in result.http_head
    assert result.origin_source_path.endswith("c.warc")


def test_revisit_resolves_via_refers_to(tmp_path):
    body = b"referred body"
    idx, _ = build(tmp_path, [
        response("urn:uuid:orig", body, date="2026-01-01T00:00:00Z"),
        revisit("urn:uuid:rev", "2026-02-01T00:00:00Z",
                digest=b32_digest(body), refers_to="urn:uuid:orig"),
    ])
    result = idx.get_by_id("urn:uuid:rev").resolve()
    assert result.body == body
    assert result.origin_record_id == "urn:uuid:orig"


def test_revisit_server_not_modified_profile(tmp_path):
    body = b"304 target body"
    idx, _ = build(tmp_path, [
        response("urn:uuid:orig", body, date="2026-01-01T00:00:00Z"),
        revisit("urn:uuid:rev", "2026-02-01T00:00:00Z",
                profile=PROFILE_304),  # no digest, no refers-to
    ])
    result = idx.get_by_id("urn:uuid:rev").resolve()
    assert result.body == body
    assert result.origin_record_id == "urn:uuid:orig"


def test_revisit_missing_target_raises(tmp_path):
    idx, _ = build(tmp_path, [
        revisit("urn:uuid:rev", "2026-02-01T00:00:00Z",
                digest=b32_digest(b"ghost")),
    ])
    with pytest.raises(RevisitTargetNotFoundError):
        idx.get_by_id("urn:uuid:rev").resolve()


def test_revisit_refers_to_missing_record_raises(tmp_path):
    body = b"x"
    idx, _ = build(tmp_path, [
        revisit("urn:uuid:rev", "2026-02-01T00:00:00Z",
                digest=b32_digest(body), refers_to="urn:uuid:gone"),
    ])
    with pytest.raises(RevisitTargetNotFoundError):
        idx.get_by_id("urn:uuid:rev").resolve()


def test_revisit_digest_mismatch_raises(tmp_path):
    idx, _ = build(tmp_path, [
        response("urn:uuid:orig", b"real body",
                 date="2026-01-01T00:00:00Z"),
        revisit("urn:uuid:rev", "2026-02-01T00:00:00Z",
                digest=b32_digest(b"different body"),
                refers_to="urn:uuid:orig"),
    ])
    with pytest.raises(RevisitDigestMismatchError) as exc:
        idx.get_by_id("urn:uuid:rev").resolve()
    assert exc.value.expected != exc.value.actual


def test_revisit_unknown_profile_without_link_raises(tmp_path):
    block = http_response(b"", status=304)
    rec = warc_record(
        "revisit", block, record_id="urn:uuid:rev",
        uri="https://example.com/", date="2026-02-01T00:00:00Z",
        extra_headers={"WARC-Profile": "http://example.invalid/profile"},
    )
    idx, _ = build(tmp_path, [rec])
    with pytest.raises(RevisitProfileError):
        idx.get_by_id("urn:uuid:rev").resolve()


def test_revisit_marked_truncated_raises(tmp_path):
    body = b"x"
    idx, _ = build(tmp_path, [
        response("urn:uuid:orig", body),
        revisit("urn:uuid:rev", "2026-02-01T00:00:00Z",
                digest=b32_digest(body), truncated="length"),
    ])
    with pytest.raises(RevisitTruncatedError):
        idx.get_by_id("urn:uuid:rev").resolve()


def test_revisit_target_truncated_raises(tmp_path):
    body = b"x"
    idx, _ = build(tmp_path, [
        response("urn:uuid:orig", body, truncated="disconnect"),
        revisit("urn:uuid:rev", "2026-02-01T00:00:00Z",
                digest=b32_digest(body), refers_to="urn:uuid:orig"),
    ])
    with pytest.raises(RevisitTruncatedError):
        idx.get_by_id("urn:uuid:rev").resolve()


def test_response_own_corrupted_digest_raises(tmp_path):
    body = b"correct bytes"
    block = http_response(body)
    # Declare a digest for different bytes while keeping block intact.
    rec = warc_record("response", block, record_id="urn:uuid:bad",
                      uri="https://example.com/",
                      payload_digest=b32_digest(b"other bytes"))
    idx, _ = build(tmp_path, [rec])
    with pytest.raises(DigestMismatchError):
        idx.get_by_id("urn:uuid:bad").resolve()


def test_revisit_points_to_non_response_raises(tmp_path):
    # Refers-To a metadata record: cannot provide HTTP payload.
    meta = warc_record("metadata", b"junk", record_id="urn:uuid:not-resp",
                       uri="https://example.com/",
                       date="2026-01-01T00:00:00Z")
    idx, _ = build(tmp_path, [
        meta,
        revisit("urn:uuid:rev", "2026-02-01T00:00:00Z",
                refers_to="urn:uuid:not-resp"),
    ])
    with pytest.raises(RevisitTargetNotFoundError):
        idx.get_by_id("urn:uuid:rev").resolve()


def test_revisit_resolves_across_files(tmp_path):
    body = b"multi file body"
    p1 = tmp_path / "a.warc"
    p2 = tmp_path / "b.warc"
    p1.write_bytes(response("urn:uuid:orig", body))
    p2.write_bytes(revisit("urn:uuid:rev", "2026-02-01T00:00:00Z",
                           digest=b32_digest(body)))
    idx = Index.create(":memory:")
    idx.add_source(p1)
    idx.add_source(p2)
    result = idx.get_by_id("urn:uuid:rev").resolve()
    assert result.body == body
    assert result.origin_source_path == str(p1)


def test_revisit_result_warnings_include_both_records(tmp_path):
    # Duplicate HTTP headers are tolerated but warned about.
    block = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: 6\r\n\r\n"
        b"warned"
    )
    rec = warc_record("response", block, record_id="urn:uuid:orig",
                      uri="https://example.com/",
                      date="2026-01-01T00:00:00Z",
                      payload_digest=b32_digest(b"warned"))
    idx, _ = build(tmp_path, [
        rec,
        revisit("urn:uuid:rev", "2026-02-01T00:00:00Z",
                digest=b32_digest(b"warned")),
    ])
    result = idx.get_by_id("urn:uuid:rev").resolve()
    assert result.body == b"warned"
    # Warnings from the origin record surface on the resolved result.
    assert result.warnings


def test_revisit_digest_profile_prefers_matching_not_just_latest(tmp_path):
    # Two captures of the URI with different bodies; the digest-named
    # revisit must resolve to the older matching one, not the newest.
    old, new = b"old body", b"new body different"
    idx, _ = build(tmp_path, [
        response("urn:uuid:old", old, date="2026-01-01T00:00:00Z"),
        response("urn:uuid:new", new, date="2026-03-01T00:00:00Z"),
        revisit("urn:uuid:rev", "2026-04-01T00:00:00Z",
                digest=b32_digest(old)),
    ])
    result = idx.get_by_id("urn:uuid:rev").resolve()
    assert result.body == old
    assert result.origin_record_id == "urn:uuid:old"
