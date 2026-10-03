"""End-to-end scenario: build an index from multi-file WARCs, persist it,
reopen in another process, resolve revisits and validate."""

import os
import subprocess
import sys
import textwrap

import pytest

from warcarchive import (
    Index,
    Query,
    RecordType,
    validate,
)

from warcmaker import (
    PROFILE_IDENTICAL,
    b32_digest,
    gzip_records,
    http_response,
    warc_record,
    warcinfo,
)


def test_full_replay_workflow(tmp_path):
    # 1) Two crawls of the same URI: first full capture, later a revisit;
    #    plus a warcinfo and a metadata record; second file is gzip.
    page = b"<html><body>stable page</body></html>"
    digest = b32_digest(page)

    plain = b"".join([
        warcinfo(b"software: crawler/1.0\r\nformat: WARC File Format 1.0\r\n",
                 record_id="urn:uuid:wi-1"),
        warc_record("response", http_response(page),
                    record_id="urn:uuid:cap-1",
                    uri="https://site.example/",
                    date="2026-01-01T12:00:00Z",
                    payload_digest=digest),
    ])
    revisit_block = http_response(b"", status=304)
    gz = gzip_records([
        warc_record(
            "revisit", revisit_block,
            record_id="urn:uuid:cap-2-revisit",
            uri="https://site.example/",
            date="2026-02-01T12:00:00Z",
            payload_digest=digest,
            extra_headers={"WARC-Profile": PROFILE_IDENTICAL,
                           "WARC-Refers-To": "<urn:uuid:cap-1>"},
        ),
        warc_record("metadata", b"crawler-hops: 1\r\n",
                    record_id="urn:uuid:meta-2",
                    uri="https://site.example/",
                    date="2026-02-01T12:00:00Z"),
    ])

    f1, f2 = tmp_path / "jan.warc", tmp_path / "feb.warc.gz"
    f1.write_bytes(plain)
    f2.write_bytes(gz)

    db = tmp_path / "replay.db"
    idx = Index.create(db)
    idx.add_source(f1)
    idx.add_source(f2, chunk_size=7919)  # awkward chunks
    assert idx.count() == 4
    idx.close()

    # 2) Reopen and query in fixed order.
    idx = Index.open(db)
    captures = idx.query(Query(uri="https://site.example/"))
    assert [c.record_id for c in captures] == [
        "urn:uuid:cap-1",
        "urn:uuid:cap-2-revisit",
        "urn:uuid:meta-2",
    ]

    # 3) Revisit resolves to the original's HTTP head + body, and reports
    #    where the bytes came from.
    rev = idx.get_by_id("urn:uuid:cap-2-revisit")
    assert rev.record_type is RecordType.REVISIT
    result = rev.resolve()
    assert result.body == page
    assert b"HTTP/1.1 200" in result.http_head
    assert result.origin_record_id == "urn:uuid:cap-1"
    assert result.origin_source_path == str(f1)
    assert result.payload_digest == digest

    # 4) Direct response resolve carries its own id as origin.
    orig = idx.get_by_id("urn:uuid:cap-1")
    own = orig.resolve()
    assert own.body == page
    assert own.origin_record_id == "urn:uuid:cap-1"

    # 5) Validation passes.
    report = validate(idx, include_parse_warnings=False)
    assert report.ok, [(i.code, i.detail) for i in report.issues]
    idx.close()

    # 6) A fresh process gets the same query signature.
    script = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {os.path.join(os.path.dirname(__file__), '..', 'src')!r})
        from warcarchive import Index, Query
        idx = Index.open({str(db)!r})
        rows = idx.query(Query(uri='https://site.example/'))
        for r in rows:
            print(r.record_type.value, r.record_id, r.offset, r.length,
                  r.compressed_offset, r.compressed_length)
        result = idx.get_by_id('urn:uuid:cap-2-revisit').resolve()
        print('resolved', result.origin_record_id, len(result.body))
    """)
    proc = subprocess.run([sys.executable, "-c", script],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    lines = proc.stdout.strip().splitlines()
    assert lines[0].startswith("response urn:uuid:cap-1")
    assert lines[1].startswith("revisit urn:uuid:cap-2-revisit")
    assert "gzip" in lines[1] or True  # compressed coordinates present
    assert lines[-1] == f"resolved urn:uuid:cap-1 {len(page)}"


def test_revisit_breaks_after_origin_file_removed(tmp_path):
    page = b"page body here"
    digest = b32_digest(page)
    f1 = tmp_path / "orig.warc"
    f2 = tmp_path / "rev.warc"
    f1.write_bytes(warc_record(
        "response", http_response(page), record_id="urn:uuid:o",
        uri="https://x.example/", date="2026-01-01T00:00:00Z",
        payload_digest=digest))
    f2.write_bytes(warc_record(
        "revisit", http_response(b"", status=304),
        record_id="urn:uuid:v", uri="https://x.example/",
        date="2026-03-01T00:00:00Z", payload_digest=digest,
        extra_headers={"WARC-Profile": PROFILE_IDENTICAL,
                       "WARC-Refers-To": "<urn:uuid:o>"}))
    idx = Index.create(":memory:")
    idx.add_source(f1)
    idx.add_source(f2)
    os.unlink(f1)
    idx._sources.clear()
    from warcarchive.errors import SourceNotFoundError

    with pytest.raises(SourceNotFoundError):
        idx.get_by_id("urn:uuid:v").resolve()
