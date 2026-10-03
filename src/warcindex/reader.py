"""Read WARC files: streaming iteration and random-access record materialization."""

from __future__ import annotations

import io
import os
from typing import BinaryIO, Iterable, Iterator

from .errors import (
    CompressionUnsupportedError,
    PayloadError,
    WarcIOError,
)
from .httpblock import (
    PayloadHasher,
    SpanReader,
    _is_http,
    open_http_body,
    parse_status_line,
    split_head,
)
from .models import Headers, PayloadData, RawRecordInfo, RecordBegin, RecordEnd
from .parser import WarcStreamParser, parse_header_block
from ._util import (
    DEFAULT_DIGEST_ALGORITHM,
    normalize_record_id,
    normalize_uri,
    normalize_warc_date,
    parse_digest,
)

_GZIP_MAGIC = b"\x1f\x8b"
_READ_CHUNK = 1024 * 1024
_HASH_CHUNK = 64 * 1024
_MAX_DIRECT_HEADER = 16 * 1024 * 1024


# ---------------------------------------------------------------------------
# Streaming iteration over a file (or file-like stream)
# ---------------------------------------------------------------------------

def iter_records(
    source: str | os.PathLike | BinaryIO,
    *,
    chunk_size: int = _READ_CHUNK,
) -> Iterator[RawRecordInfo]:
    """Yield one :class:`RawRecordInfo` per record in *source*.

    *source* is a path or a binary stream.  The stream is read in chunks
    (default 1 MiB); per-record buffers never exceed the chunk size plus one
    record header, so large files do not inflate memory use.
    """
    close_after = False
    if hasattr(source, "read"):
        fh = source
        path = getattr(source, "name", None)
    else:
        path = os.fspath(source)
        try:
            fh = open(path, "rb", buffering=0)
        except OSError as exc:
            raise WarcIOError(f"cannot open WARC file {path!r}: {exc}") from exc
        close_after = True

    try:
        first = fh.read(2)
        if first == _GZIP_MAGIC:
            raise CompressionUnsupportedError(
                f"{path or 'stream'} appears to be gzip compressed; "
                "decompress it before indexing"
            )
        parser = WarcStreamParser()
        current = None  # (begin, hasher, computed_algo, warnings)
        declared_warnings: list[str] = []

        def _drain(events) -> list[RawRecordInfo]:
            nonlocal current, declared_warnings
            finished: list[RawRecordInfo] = []
            for event in events:
                if isinstance(event, RecordBegin):
                    declared_warnings = list(event.warnings)
                    current = _open_record_state(event, declared_warnings)
                elif isinstance(event, PayloadData):
                    if current is not None:
                        current[1].update(event.data)
                elif isinstance(event, RecordEnd):
                    if current is not None:
                        finished.append(
                            _close_record_state(current, event, path, declared_warnings)
                        )
                        current = None
            return finished

        pending = first
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                data = pending
                pending = b""
            else:
                data = pending + chunk
                pending = b""
            if data:
                for info in _drain(parser.feed(data)):
                    yield info
            if not chunk:
                break

        for info in _drain(parser.feed_eof()):
            yield info
    finally:
        if close_after:
            fh.close()


def _open_record_state(begin: RecordBegin, declared_warnings: list[str]):
    h = begin.warc_headers
    algo = DEFAULT_DIGEST_ALGORITHM
    declared = h.get("WARC-Payload-Digest")
    if declared is not None:
        try:
            algo, _ = parse_digest(
                declared.decode("utf-8", "replace"), declared_warnings
            )
        except Exception:
            algo = DEFAULT_DIGEST_ALGORITHM
    is_http = _is_http(
        h.get("Content-Type"),
        h.get("WARC-Target-URI"),
    ) and begin.record_type in ("response", "metadata", "resource")
    # revisit records carry no HTTP message; their digest is declared.
    hasher = PayloadHasher(algo, is_http=is_http)
    return (begin, hasher, algo, declared_warnings)


def _close_record_state(state, end: RecordEnd, path, warnings_passthrough):
    begin, hasher, algo, declared_warnings = state
    hasher.finish()
    h = begin.warc_headers

    rid = normalize_record_id(h.get("WARC-Record-ID").decode("utf-8", "replace"))

    uri = h.get("WARC-Target-URI")
    target_uri = normalize_uri(uri.decode("utf-8", "replace")) if uri is not None else None

    date_raw = h.get("WARC-Date")
    if date_raw is not None:
        date, epoch = normalize_warc_date(
            date_raw.decode("utf-8", "replace"), declared_warnings
        )
    else:
        date, epoch = None, None

    declared_digest = None
    declared_algo = None
    d = h.get("WARC-Payload-Digest")
    if d is not None:
        try:
            declared_algo, declared_digest = parse_digest(
                d.decode("utf-8", "replace"), declared_warnings
            )
        except Exception:
            declared_warnings.append(
                f"unparseable WARC-Payload-Digest: {d!r}"
            )

    refers_to = h.get("WARC-Refers-To")
    refers = (
        normalize_record_id(refers_to.decode("utf-8", "replace"))
        if refers_to is not None
        else None
    )
    profile = h.get("WARC-Profile")
    profile_s = profile.decode("utf-8", "replace").strip() if profile is not None else None

    truncated = end.truncated
    reason = end.trunc_reason
    if hasher.truncated and not truncated:
        truncated = True
        reason = reason or hasher.trunc_reason or "length"
    all_warnings = list(dict.fromkeys(
        list(begin.warnings) + list(end.warnings) + list(hasher.warnings)
    ))

    info = RawRecordInfo(
        record_id=rid,
        record_type=begin.record_type,
        target_uri=target_uri,
        date=date,
        epoch=epoch,
        declared_payload_digest=declared_digest,
        declared_payload_digest_algorithm=declared_algo,
        computed_payload_digest=hasher.digest(),
        computed_payload_digest_algorithm=algo,
        refers_to=refers,
        revisit_profile=profile_s,
        warc_headers=h,
        http_status=hasher.http_status,
        offset=begin.offset,
        length=end.length,
        truncated=truncated,
        trunc_reason=reason,
        warnings=tuple(all_warnings),
    )
    return info


# ---------------------------------------------------------------------------
# Random access: materialize one located record
# ---------------------------------------------------------------------------

class ResolvedPayload:
    """The materialized HTTP headers and body of one record.

    For ordinary records ``payload_record_id`` equals the record's own id;
    for a revisit it is the id of the record whose payload was actually
    served (the payload provenance required for replay).

    Use :meth:`read` to materialize the body (records are usually small
    enough), or :meth:`open` / context-manager use for streaming large
    bodies.  The body is HTTP-decoded: ``Transfer-Encoding: chunked`` framing
    is removed.
    """

    def __init__(
        self,
        *,
        record_id: str,
        record_type: str,
        payload_record_id: str,
        is_revisit: bool,
        http_status: int | None,
        http_headers: Headers | None,
        http_head_raw: bytes | None,
        body_stream,
        body_is_block: bool,
        truncated: bool,
        trunc_reason: str | None,
        warnings: Iterable[str] = (),
    ) -> None:
        self.record_id = record_id
        self.record_type = record_type
        self.payload_record_id = payload_record_id
        self.is_revisit = is_revisit
        self.http_status = http_status
        self.http_headers = http_headers
        self.http_head_raw = http_head_raw
        self._stream = body_stream
        self.body_is_block = body_is_block
        self.truncated = truncated
        self.trunc_reason = trunc_reason
        self.warnings = tuple(warnings)

    # -- header convenience -------------------------------------------------

    @property
    def is_http(self) -> bool:
        return self.http_headers is not None

    def header(self, name: str) -> bytes | None:
        if self.http_headers is None:
            return None
        return self.http_headers.get(name)

    # -- body access --------------------------------------------------------

    def open(self):
        """Return the underlying binary body stream (caller closes it)."""
        return self._stream

    def read(self) -> bytes:
        """Read and return the full decoded entity body."""
        return self._stream.read()

    def stream(self, chunk_size: int = _HASH_CHUNK):
        """Yield decoded body chunks without loading it all into memory."""
        while True:
            chunk = self._stream.read(chunk_size)
            if not chunk:
                return
            yield chunk

    def close(self) -> None:
        self._stream.close()

    def __enter__(self) -> "ResolvedPayload":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"ResolvedPayload(record_id={self.record_id!r}, "
            f"type={self.record_type!r}, http={self.is_http}, "
            f"payload_record_id={self.payload_record_id!r}, "
            f"truncated={self.truncated})"
        )


def materialize(
    path: str,
    offset: int,
    length: int,
    *,
    expected_id: str | None = None,
) -> ResolvedPayload:
    """Open the record located at *offset* in *path* and return its payload.

    Reads the WARC header directly, then decodes the record block.  Raises
    :class:`TruncatedRecordError` for WARC-level truncation.  Header/trailer
    structural problems raise :class:`WarcFormatError` subclasses.
    """
    try:
        fh = open(path, "rb", buffering=0)
    except OSError as exc:
        raise WarcIOError(f"cannot open WARC file {path!r}: {exc}") from exc
    try:
        fh.seek(offset)
        header_raw = _read_header_block(fh, expected_id)
        rtype, warc_headers, _warn = parse_header_block(header_raw)

        clen_raw = warc_headers.get("Content-Length")
        try:
            clen = int(clen_raw.decode("ascii").strip())
        except (AttributeError, ValueError):
            raise PayloadError(
                f"record at {path}:{offset} has invalid Content-Length"
            )

        rid = normalize_record_id(
            warc_headers.get("WARC-Record-ID").decode("utf-8", "replace")
        )
        trunc = warc_headers.get("WARC-Truncated")
        truncated = trunc is not None
        trunc_reason = (
            trunc.decode("utf-8", "replace").strip() if trunc is not None else None
        )

        block_start = fh.tell()
        # never read beyond the indexed record length
        remaining = min(clen, length - (block_start - offset))

        is_http = _is_http(
            warc_headers.get("Content-Type"),
            warc_headers.get("WARC-Target-URI"),
        ) and rtype in ("response", "metadata", "resource")
        # revisit records carry no HTTP message of their own; their payload is
        # obtained by resolving the pointed-to record instead.

        if not is_http:
            stream = io.BufferedReader(SpanReader(fh, remaining))
            return ResolvedPayload(
                record_id=rid,
                record_type=rtype,
                payload_record_id=rid,
                is_revisit=False,
                http_status=None,
                http_headers=None,
                http_head_raw=None,
                body_stream=stream,
                body_is_block=True,
                truncated=truncated,
                trunc_reason=trunc_reason or ("unspecified" if truncated else None),
                warnings=(),
            )

        head_raw, http_headers, status = _read_http_head(fh, remaining)
        block_left = remaining - len(head_raw)
        raw_body = open_http_body(fh, http_headers, status or 0, block_left)
        body = io.BufferedReader(raw_body)
        return ResolvedPayload(
            record_id=rid,
            record_type=rtype,
            payload_record_id=rid,
            is_revisit=False,
            http_status=status,
            http_headers=http_headers,
            http_head_raw=head_raw,
            body_stream=body,
            body_is_block=False,
            truncated=truncated,
            trunc_reason=trunc_reason or ("unspecified" if truncated else None),
            warnings=(),
        )
    except Exception:
        fh.close()
        raise


def _read_header_block(fh, expected_id: str | None) -> bytes:
    """Read a WARC header block (through the blank line) from *fh*.

    On return *fh* is positioned at the first block byte.
    """
    from .errors import WarcHeaderError

    buf = bytearray()
    start = fh.tell()
    while True:
        found = -1
        sep_used = b""
        for sep in (b"\r\n\r\n", b"\n\n", b"\r\r"):
            idx = bytes(buf).find(sep)
            if idx >= 0 and (found < 0 or idx < found):
                found, sep_used = idx, sep
        if found >= 0:
            end = found + len(sep_used)
            raw = bytes(buf[:end])
            fh.seek(start + end)
            return raw
        chunk = fh.read(8192)
        if not chunk:
            if buf.strip():
                raise WarcHeaderError(
                    "record header block runs to EOF without a blank line", start
                )
            return bytes(buf)
        buf.extend(chunk)
        if len(buf) > _MAX_DIRECT_HEADER:
            raise WarcHeaderError("WARC header block exceeds maximum size", start)


def _read_http_head(fh, remaining: int) -> tuple[bytes, Headers, int | None]:
    """Read an HTTP message head within the WARC block; return head bytes etc.

    On return the file position is at the first body byte.
    """
    buf = bytearray()
    while True:
        parsed = split_head(bytes(buf))
        if parsed is not None:
            status_line, headers, body = parsed
            blob = bytes(buf)
            idx_crlf = blob.find(b"\r\n\r\n")
            idx_lf = blob.find(b"\n\n")
            idx_cr = blob.find(b"\r\r")
            best = min(
                (i for i in (idx_crlf, idx_lf, idx_cr) if i >= 0),
            )
            sep_len = 4 if best == idx_crlf and idx_crlf >= 0 else 2
            head_end = best + sep_len
            overread = len(blob) - head_end
            if overread > 0:
                fh.seek(fh.tell() - overread)
            status, _ = parse_status_line(status_line)
            return blob[:head_end], headers, status
        want = min(8192, remaining - len(buf))
        if want <= 0:
            raise PayloadError("incomplete HTTP header in record block")
        chunk = fh.read(want)
        if not chunk:
            raise PayloadError("HTTP record block ends before header terminator")
        buf.extend(chunk)
        if len(buf) > _MAX_DIRECT_HEADER:
            raise PayloadError("HTTP header block exceeds maximum size")


def stream_hash_payload(resolved: ResolvedPayload, algorithm: str) -> str:
    """Hash the decoded body of *resolved*, streaming in bounded chunks."""
    from ._util import b32encode, new_hasher

    h = new_hasher(algorithm)
    for chunk in resolved.stream():
        h.update(chunk)
    return b32encode(h.digest())
