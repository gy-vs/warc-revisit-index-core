import os
import subprocess
import sys

import pytest

from warcarchive import (
    Index,
    Query,
    RecordNotFoundError,
    DuplicateRecordIdError,
    RecordType,
    read_stream,
)

from warcmaker import (
    PROFILE_IDENTICAL,
    b32_digest,
    gzip_records,
    http_response,
    warc_record,
    warcinfo,
)


def make_warc(captures, gzip=False):
    """captures: list of (kind, dict) tuples."""
    records = []
    for kind, params in captures:
        if kind == "response":
            body = params["body"]
            block = http_response(
                body,
                status=params.get("status", 200),
                chunked=params.get("chunked", False),
                headers=params.get("headers"),
            )
            rec = warc_record(
                "response", block,
                record_id=params.get("id"),
                uri=params.get("uri", "https://example.com/"),
                date=params.get("date", "2026-01-01T00:00:00Z"),
                payload_digest=params.get("digest", b32_digest(body)),
                extra_headers=params.get("warc_headers"),
                truncated=params.get("truncated"),
            )
        elif kind == "revisit":
            head = http_response(b"", status=304,
                                 headers=params.get("headers"))
            rec = warc_record(
                "revisit",
                params.get("block", head),
                record_id=params.get("id"),
                uri=params.get("uri", "https://example.com/"),
                date=params["date"],
                payload_digest=params.get("digest"),
                extra_headers=params.get("warc_headers", {
                    "WARC-Profile": params.get("profile", PROFILE_IDENTICAL),
                    **({"WARC-Refers-To": f"<{params['refers_to']}>"}
                       if params.get("refers_to") else {}),
                }),
                truncated=params.get("truncated"),
            )
        elif kind == "warcinfo":
            rec = warcinfo(params.get("payload", b"software: x\r\n"),
                           record_id=params.get("id", "urn:uuid:wi"))
        elif kind == "metadata":
            rec = warc_record("metadata", params["body"],
                              record_id=params.get("id"),
                              uri=params.get("uri"),
                              date=params.get("date", "2026-01-01T00:00:00Z"))
        else:
            raise AssertionError(kind)
        records.append(rec)
    data = gzip_records(records) if gzip else b"".join(records)
    return data


@pytest.fixture
def warc_path(tmp_path):
    body1, body2 = b"hello world", b"hello again"
    data = make_warc([
        ("warcinfo", {"id": "urn:uuid:wi"}),
        ("response", {"id": "urn:uuid:r1", "body": body1,
                      "date": "2026-01-01T00:00:00Z"}),
        ("response", {"id": "urn:uuid:r2", "body": body2,
                      "date": "2026-02-01T00:00:00Z"}),
        ("metadata", {"id": "urn:uuid:m1", "body": b"meta!",
                      "uri": "https://example.com/",
                      "date": "2026-03-01T00:00:00Z"}),
    ])
    p = tmp_path / "crawl.warc"
    p.write_bytes(data)
    return p


def test_ingest_and_query_by_uri_id_digest(warc_path, tmp_path):
    idx = Index.create(tmp_path / "i.db")
    views = idx.add_source(warc_path)
    assert len(views) == 4
    assert idx.count() == 4

    by_uri = idx.query(Query(uri="https://example.com/"))
    ids = [v.record_id for v in by_uri]
    assert ids == ["urn:uuid:r1", "urn:uuid:r2", "urn:uuid:m1"]

    one = idx.get_by_id("urn:uuid:r1")
    assert one.record_type is RecordType.RESPONSE
    assert one.http_status == 200
    assert one.offset >= 0 and one.length > 0

    by_digest = idx.query(Query(payload_digest=b32_digest(b"hello world")))
    assert [v.record_id for v in by_digest] == ["urn:uuid:r1"]

    # Digest query also accepts the raw WARC header spelling (with prefix).
    assert idx.query(Query(payload_digest="sha1:" + b32_digest(b"hello world").split(":", 1)[1]))
    idx.close()


def test_same_uri_different_times_are_distinct_and_stable(warc_path, tmp_path):
    idx = Index.create(":memory:")
    idx.add_source(warc_path)
    a = idx.query(Query(uri="https://example.com/"))
    b = idx.query(Query(uri="https://example.com/"))
    assert [v.record_id for v in a] == [v.record_id for v in b]
    assert a[0].date != a[1].date
    assert a[0].record_id != a[1].record_id


def test_date_range_query(warc_path):
    idx = Index.create(":memory:")
    idx.add_source(warc_path)
    from datetime import datetime, timezone
    middle = idx.query(Query(
        uri="https://example.com/",
        from_date=datetime(2026, 1, 15, tzinfo=timezone.utc),
    ))
    assert {v.record_id for v in middle} == {"urn:uuid:r2", "urn:uuid:m1"}


def test_get_by_unknown_id_raises():
    idx = Index.create(":memory:")
    with pytest.raises(RecordNotFoundError):
        idx.get_by_id("urn:uuid:nope")


def test_payload_read_plain(warc_path):
    idx = Index.create(":memory:")
    idx.add_source(warc_path)
    view = idx.get_by_id("urn:uuid:r1")
    assert view.payload_bytes() == b"hello world"
    assert b"HTTP/1.1 200" in view.http_head
    # metadata payload is the raw block
    meta = idx.get_by_id("urn:uuid:m1")
    assert meta.payload_bytes() == b"meta!"


def test_chunked_payload_is_dechunked(tmp_path):
    body = b"dechunked-payload-12345"
    data = make_warc([
        ("response", {"id": "urn:uuid:c", "body": body, "chunked": True}),
    ])
    p = tmp_path / "c.warc"
    p.write_bytes(data)
    idx = Index.create(":memory:")
    idx.add_source(p)
    view = idx.get_by_id("urn:uuid:c")
    assert view.payload_bytes() == body


def test_stream_ingest_arbitrary_chunks(tmp_path):
    body = b"stream body"
    data = make_warc([("response", {"id": "urn:uuid:s", "body": body})])
    p = tmp_path / "stream.warc"
    p.write_bytes(data)
    idx = Index.create(":memory:")

    def chunks():
        for i in range(0, len(data), 37):
            yield data[i : i + 37]

    views = read_stream(idx, chunks(), source_path=str(p))
    assert len(views) == 1
    assert views[0].payload_bytes() == body


def test_persistence_roundtrip_new_process(warc_path, tmp_path):
    db = tmp_path / "idx.db"
    idx = Index.create(db)
    idx.add_source(warc_path)
    first = idx.query(Query(uri="https://example.com/"))
    signature = [(v.record_id, v.offset, v.length, tuple(v.warnings))
                 for v in first]
    idx.close()

    # Re-open in the same process.
    idx2 = Index.open(db)
    second = idx2.query(Query(uri="https://example.com/"))
    assert [(v.record_id, v.offset, v.length, tuple(v.warnings))
            for v in second] == signature
    assert second[0].payload_bytes() == b"hello world"
    idx2.close()

    # And from a fresh Python process.
    code = (
        "import sys; sys.path.insert(0, %r);"
        "from warcarchive import Index, Query;"
        "idx = Index.open(%r);"
        "rows = idx.query(Query(uri='https://example.com/'));"
        "print([(r.record_id, r.offset, r.length, r.payload_bytes()) "
        "for r in rows])"
        % (os.path.join(os.path.dirname(__file__), "..", "src"),
           str(db))
    )
    out = subprocess.run([sys.executable, "-c", code],
                         capture_output=True, text=True, check=True)
    assert "urn:uuid:r1" in out.stdout
    assert "b'hello world'" in out.stdout


def test_gzip_warc_roundtrip_and_payload(tmp_path):
    body = b"gzipped body"
    data = make_warc([
        ("response", {"id": "urn:uuid:gz", "body": body}),
    ], gzip=True)
    p = tmp_path / "c.warc.gz"
    p.write_bytes(data)
    idx = Index.create(":memory:")
    views = idx.add_source(p)
    v = views[0]
    assert v.handle.compressed_offset == 0
    assert v.handle.compressed_length == len(data)
    assert v.payload_bytes() == body


def test_duplicate_record_id_within_source_raises(tmp_path):
    block = http_response(b"x")
    rec = warc_record("response", block, record_id="urn:uuid:dup")
    p = tmp_path / "d.warc"
    p.write_bytes(rec + rec)
    idx = Index.create(":memory:")
    with pytest.raises(DuplicateRecordIdError):
        idx.add_source(p)


def test_re_adding_source_replaces_rows(tmp_path):
    body = b"first version"
    data = make_warc([("response", {"id": "urn:uuid:v", "body": body,
                                    "date": "2026-01-01T00:00:00Z"})])
    p = tmp_path / "r.warc"
    p.write_bytes(data)
    idx = Index.create(":memory:")
    idx.add_source(p)
    body2 = b"second version, longer"
    p.write_bytes(make_warc([
        ("response", {"id": "urn:uuid:v", "body": body2,
                      "date": "2026-01-01T00:00:00Z"})]))
    idx.add_source(p)
    assert idx.count() == 1
    assert idx.get_by_id("urn:uuid:v").payload_bytes() == body2
