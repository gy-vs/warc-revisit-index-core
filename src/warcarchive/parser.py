"""Streaming WARC parser.

Two layers live here:

* :class:`WarcStreamParser` parses an *uncompressed* WARC byte stream fed in
  arbitrarily sized chunks.  Record bodies are never retained, so memory use
  is independent of file/record size.
* :class:`GzipWarcStreamParser` handles WARCs compressed as one gzip member
  per record (``Content-Encoding: gzip`` WARCs as written by wget/heritrix),
  recording both logical and compressed coordinates.
* :class:`RecordFeeder` auto-detects gzip from the first two bytes.
"""

from __future__ import annotations

import dataclasses
import re
import zlib

from .digest import parse_digest
from .errors import GzipFormatError, UnknownDigestError, WarcFormatError
from .httpmsg import (
    HTTP_PREFIX_LIMIT,
    find_head_end,
    parse_http_head,
)
from .model import (
    W_BAD_TERMINATOR,
    W_CONTENT_LENGTH_MISMATCH,
    W_DUPLICATE_HEADER,
    W_GZIP_TRUNCATED,
    W_HTTP_PREFIX_LIMIT,
    W_INVALID_DATE,
    W_INVALID_DIGEST,
    W_MISSING_DATE,
    W_MISSING_RECORD_ID,
    W_MISSING_TERMINATOR,
    W_MISSING_URI,
    W_NOT_HTTP,
    W_RECORD_TRUNCATED,
    W_UNKNOWN_TYPE,
    W_WARC_VERSION,
    HeaderMap,
    RecordHandle,
    RecordType,
    WarcHead,
    normalize_record_id,
    normalize_uri,
    parse_warc_date,
    truncation_reason,
)

_WS = b"\r\n"
_HEADER_LIMIT = 1 << 20  # 1 MiB of WARC header is absurd; anything more = junk
_VERSION_RE = re.compile(r"^WARC/(\d+\.\d+)$")
_URI_TYPES = {
    RecordType.RESPONSE,
    RecordType.RESOURCE,
    RecordType.REQUEST,
    RecordType.METADATA,
    RecordType.REVISIT,
    RecordType.CONVERSION,
}
_HTTP_TYPES = {RecordType.RESPONSE, RecordType.REVISIT}


def _dedup_warnings(warnings: list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for code in warnings:
        if code not in seen:
            seen.add(code)
            out.append(code)
    return tuple(out)


def parse_warc_head(raw: bytes) -> tuple[WarcHead, list[str]]:
    """Parse one WARC header block (``raw`` includes the blank-line end)."""
    warnings: list[str] = []
    text = raw.decode("utf-8", errors="replace")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if lines and lines[-1] == "\r":
        lines[-1] = lines[-1][:-1]
    if not lines:
        raise WarcFormatError("empty WARC header")

    version_line = lines[0]
    if version_line.endswith("\r"):
        version_line = version_line[:-1]
    match = _VERSION_RE.match(version_line)
    if not match:
        if version_line.upper().startswith("WARC/"):
            warnings.append(W_WARC_VERSION)
            version = version_line[5:].strip()
        else:
            raise WarcFormatError(f"not a WARC record: {version_line!r}")
    else:
        version = match.group(1)

    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    prev_name: str | None = None
    for line in lines[1:]:
        if line.endswith("\r"):
            line = line[:-1]
        if line == "":
            continue
        if line[0] in (" ", "\t") and prev_name is not None:
            # Obsolete line folding: join onto the previous header.
            name, value = pairs[-1]
            pairs[-1] = (name, value + " " + line.strip())
            continue
        if ":" not in line:
            raise WarcFormatError(f"malformed WARC header line: {line!r}")
        name, value = line.split(":", 1)
        name = name.strip()
        value = value.strip()
        prev_name = name
        if name.lower() in seen:
            warnings.append(W_DUPLICATE_HEADER)
            continue
        seen.add(name.lower())
        pairs.append((name, value))

    fields = HeaderMap(pairs)
    if fields.get("WARC-Type") is None:
        raise WarcFormatError("WARC-Type header is required")
    length_raw = fields.get("Content-Length")
    if length_raw is None:
        raise WarcFormatError("Content-Length header is required")
    try:
        int(length_raw.strip())
    except ValueError:
        raise WarcFormatError(f"non-integer Content-Length: {length_raw!r}") from None
    return WarcHead(version=version, fields=fields, raw=raw), warnings


class WarcStreamParser:
    """Incremental parser for an uncompressed WARC stream.

    Usage::

        parser = WarcStreamParser()
        records = parser.feed(chunk)   # zero or more completed records
        records += parser.finish()     # flush the final record at EOF

    The parser holds at most a few MiB (header + HTTP-head prefix scan)
    regardless of the size of the bodies flowing through it.
    """

    _HEADER = 1
    _BLOCK = 2
    _TAIL = 3

    def __init__(self) -> None:
        self._buf = bytearray()
        self._state = self._HEADER
        self._pos = 0
        self._record_start = 0
        self._head: WarcHead | None = None
        self._warnings: list[str] = []
        self._head_len = 0
        self._content_length = 0
        self._block_consumed = 0
        self._headbuf = b""
        self._http_head: bytes | None = None
        self._payload_offset = 0
        self._http_status: int | None = None
        self._http_chunked = False
        self._http_decided = False
        self._tail_warn: str | None = None

    @property
    def logical_pos(self) -> int:
        """Number of logical WARC bytes consumed so far."""
        return self._pos

    # -- public API --------------------------------------------------------

    def feed(self, data: bytes | bytearray | memoryview) -> list[RecordHandle]:
        self._buf += bytes(data)
        records: list[RecordHandle] = []
        # Drive the state machine until neither the state changes, bytes are
        # consumed nor block content progresses: we need more input then.
        while self._buf:
            before_state = self._state
            before_len = len(self._buf)
            before_consumed = self._block_consumed
            if self._state == self._HEADER:
                self._consume_leading_ws()
                self._try_header()
            elif self._state == self._BLOCK:
                emitted = self._consume_block()
                if emitted is not None:
                    records.append(emitted)
            elif self._state == self._TAIL:
                emitted = self._consume_tail()
                if emitted is not None:
                    records.append(emitted)
            stalled = (
                self._state == before_state
                and len(self._buf) == before_len
                and self._block_consumed == before_consumed
            )
            if stalled:
                break
        return records

    def finish(self) -> list[RecordHandle]:
        """Signal end of stream and return any record that was still open."""
        records: list[RecordHandle] = []
        if self._state == self._HEADER:
            self._consume_leading_ws()
            if bytes(self._buf).strip(b"\r\n"):
                if self._force_truncated:
                    # Container (gzip member) ended with a partial WARC
                    # header: emit no record, just absorb the bytes.
                    self._pos += len(self._buf)
                    self._buf.clear()
                    self._force_truncated = False
                else:
                    raise WarcFormatError(
                        f"{len(self._buf)} trailing bytes after last record"
                    )
            self._buf.clear()
        elif self._state == self._BLOCK:
            if self._block_consumed < self._content_length:
                self._warnings.append(W_RECORD_TRUNCATED)
                remaining = bytes(self._buf)
                self._inspect_block(remaining, final=True)
                self._block_consumed += len(remaining)
                self._pos += len(remaining)
                self._buf.clear()
            self._finalize_http_scan(final=True)
            records.append(self._emit(tail_len=0,
                                      tail_warn=W_MISSING_TERMINATOR))
            self._force_truncated = False
        elif self._state == self._TAIL:
            remaining = bytes(self._buf)
            if remaining and not remaining.strip(b"\r\n"):
                self._pos += len(remaining)
                self._buf.clear()
                records.append(
                    self._emit(tail_len=len(remaining), tail_warn=W_MISSING_TERMINATOR)
                )
            elif remaining:
                raise WarcFormatError("trailing non-newline bytes after record")
            else:
                records.append(self._emit(tail_len=0, tail_warn=W_MISSING_TERMINATOR))
        return records

    # -- HEADER state ------------------------------------------------------

    def _consume_leading_ws(self) -> bool:
        i = 0
        for i, byte in enumerate(self._buf):
            if byte not in (0x0D, 0x0A):
                break
        else:
            i = len(self._buf)
        if i:
            del self._buf[:i]
            self._pos += i
            return True
        return False

    def _try_header(self) -> RecordHandle | None:
        found = find_head_end(bytes(self._buf[:_HEADER_LIMIT + 4]))
        if found is None:
            if len(self._buf) > _HEADER_LIMIT:
                raise WarcFormatError("WARC header larger than 1 MiB")
            return None
        end, _bare = found
        raw = bytes(self._buf[:end])
        del self._buf[:end]
        self._record_start = self._pos
        self._pos += end
        self._head_len = end
        self._head, self._warnings = parse_warc_head(raw)
        self._content_length = int(self._head.fields.get("Content-Length").strip())
        self._begin_block()
        # A zero-length block goes straight to tail handling.
        if self._content_length == 0:
            self._state = self._TAIL
            self._tail_warn = None
        else:
            self._state = self._BLOCK
        return None

    # -- BLOCK state -------------------------------------------------------

    def _begin_block(self) -> None:
        assert self._head is not None
        self._block_consumed = 0
        self._headbuf = b""
        self._http_head = None
        self._payload_offset = 0
        self._http_status = None
        self._http_chunked = False
        self._http_decided = self._head_type() not in _HTTP_TYPES
        self._tail_warn = None

    def _head_type(self) -> RecordType:
        assert self._head is not None
        return RecordType.parse(self._head.fields.get("WARC-Type", ""))

    def _consume_block(self) -> RecordHandle | None:
        remaining = self._content_length - self._block_consumed
        take = min(remaining, len(self._buf))
        if take:
            chunk = bytes(self._buf[:take])
            del self._buf[:take]
            self._inspect_block(chunk, final=False)
            self._block_consumed += take
            self._pos += take
        if self._block_consumed < self._content_length:
            return None
        self._finalize_http_scan(final=False)
        self._state = self._TAIL
        self._tail_warn = None
        return None

    def _inspect_block(self, chunk: bytes, final: bool) -> None:
        if self._http_decided:
            return
        room = HTTP_PREFIX_LIMIT - len(self._headbuf)
        if room > 0:
            self._headbuf += chunk[:room]
        found = find_head_end(self._headbuf) if self._headbuf else None
        if found is not None:
            end, bare_lf = found
            head, http_warnings = parse_http_head(self._headbuf[:end], bare_lf)
            self._warnings.extend(http_warnings)
            if head is not None and head.status is not None:
                self._http_head = head.raw
                self._http_status = head.status
                self._http_chunked = head.chunked
                self._payload_offset = end
                cl = head.content_length
                if cl is not None and not head.chunked:
                    declared_block_payload = self._content_length - end
                    if cl != declared_block_payload and self._head_type() is RecordType.RESPONSE:
                        # Informational only: servers lie and recrawls differ.
                        self._warnings.append(W_CONTENT_LENGTH_MISMATCH)
            else:
                self._warnings.append(W_NOT_HTTP)
            self._http_decided = True
            self._headbuf = b""
        elif len(self._headbuf) >= HTTP_PREFIX_LIMIT:
            self._warnings.append(W_HTTP_PREFIX_LIMIT)
            self._warnings.append(W_NOT_HTTP)
            self._http_decided = True
            self._headbuf = b""

    def _finalize_http_scan(self, final: bool) -> None:
        if not self._http_decided:
            # Block ended before any blank line: not HTTP.
            self._warnings.append(W_NOT_HTTP)
            self._http_decided = True
            self._headbuf = b""

    # -- TAIL state --------------------------------------------------------

    def _consume_tail(self) -> RecordHandle | None:
        data = bytes(self._buf)
        if len(data) >= 4:
            if data[:4] == b"\r\n\r\n":
                del self._buf[:4]
                self._pos += 4
                return self._emit(tail_len=4, tail_warn=None)
            k = 0
            while k < len(data) and data[k] in (0x0D, 0x0A) and k < 4:
                k += 1
            if k >= 2:
                del self._buf[:k]
                self._pos += k
                return self._emit(tail_len=k, tail_warn=W_BAD_TERMINATOR)
            if k == 1:
                del self._buf[:k]
                self._pos += k
                return self._emit(tail_len=k, tail_warn=W_MISSING_TERMINATOR)
            # No separator at all; the next byte starts the following record.
            self._state = self._HEADER
            return self._emit(tail_len=0, tail_warn=W_MISSING_TERMINATOR)

        # Fewer than four bytes: only decide once we see a non-newline.
        k = 0
        while k < len(data) and data[k] in (0x0D, 0x0A):
            k += 1
        if k < len(data):
            if k == 0:
                # Non-newline first: this is the start of a new record; keep
                # the byte and close the current record without a separator.
                self._state = self._HEADER
                return self._emit(tail_len=0, tail_warn=W_MISSING_TERMINATOR)
            del self._buf[:k]
            self._pos += k
            warn = W_BAD_TERMINATOR if k >= 2 else W_MISSING_TERMINATOR
            return self._emit(tail_len=k, tail_warn=warn)
        return None  # wait for more input (or finish())

    # -- emission ----------------------------------------------------------

    def _emit(self, tail_len: int, tail_warn: str | None) -> RecordHandle:
        assert self._head is not None
        head = self._head
        warnings = list(self._warnings)
        if tail_warn:
            warnings.append(tail_warn)

        fields = head.fields
        rtype = RecordType.parse(fields.get("WARC-Type", ""))
        if rtype is RecordType.UNKNOWN:
            warnings.append(W_UNKNOWN_TYPE)

        record_id = normalize_record_id(fields.get("WARC-Record-ID"))
        if record_id is None:
            warnings.append(W_MISSING_RECORD_ID)
            record_id = self._synthetic_id(head.raw)

        date_raw = fields.get("WARC-Date")
        date = parse_warc_date(date_raw)
        if date_raw is None:
            warnings.append(W_MISSING_DATE)
        elif date is None:
            warnings.append(W_INVALID_DATE)

        uri = normalize_uri(fields.get("WARC-Target-URI"))
        if uri is None and rtype in _URI_TYPES:
            warnings.append(W_MISSING_URI)

        payload_digest = self._canon_digest(
            fields.get("WARC-Payload-Digest"), warnings
        )
        block_digest = self._canon_digest(fields.get("WARC-Block-Digest"), warnings)

        block_len = self._block_consumed
        handle = RecordHandle(
            record_id=record_id,
            record_type=rtype,
            target_uri=uri,
            date=date,
            payload_digest=payload_digest,
            block_digest=block_digest,
            refers_to=normalize_record_id(fields.get("WARC-Refers-To")),
            profile=(fields.get("WARC-Profile") or "").strip() or None,
            ip_address=(fields.get("WARC-IP-Address") or "").strip() or None,
            truncated=truncation_reason(head),
            warcinfo_id=normalize_record_id(fields.get("WARC-Warcinfo-ID")),
            http_status=self._http_status,
            http_head=bytes(self._http_head or b""),
            payload_offset=self._payload_offset,
            http_chunked=self._http_chunked,
            content_length=block_len,
            offset=self._record_start,
            length=self._head_len + block_len + tail_len,
            head_length=self._head_len,
            block_length=block_len,
            tail_length=tail_len,
            warnings=_dedup_warnings(warnings),
        )
        self._reset()
        return handle

    @staticmethod
    def _canon_digest(raw: str | None, warnings: list[str]) -> str | None:
        if raw is None:
            return None
        try:
            digest = parse_digest(raw)
        except UnknownDigestError:
            warnings.append(W_INVALID_DIGEST)
            return raw.strip()
        return str(digest) if digest else None

    def _synthetic_id(self, head_raw: bytes) -> str:
        import hashlib

        token = hashlib.sha1(head_raw).hexdigest()[:16]
        return f"urn:warcarchive:synthetic:offset-{self._record_start}:{token}"

    def _reset(self) -> None:
        self._state = self._HEADER
        self._head = None
        self._warnings = []
        self._content_length = 0
        self._block_consumed = 0
        self._headbuf = b""
        self._http_head = None
        self._payload_offset = 0
        self._http_status = None
        self._http_chunked = False
        self._http_decided = False
        self._tail_warn = None
        self._force_truncated = False

    def mark_truncated(self) -> None:
        """Signal that the surrounding container (e.g. a gzip member) ended
        before this record's declared Content-Length was consumed."""
        self._force_truncated = True


# ---------------------------------------------------------------------------
# gzip per-record support
# ---------------------------------------------------------------------------

_GZIP_MAGIC = b"\x1f\x8b"


class GzipWarcStreamParser:
    """Parse a gzip-compressed WARC (one gzip member per record, convention).

    Output handles carry both logical (uncompressed) and compressed
    (on-disk) coordinates.  Decompression is incremental: decompressed bytes
    flow straight into the inner WARC parser and are released, so a single
    huge member costs only a few MiB.

    Records are released when their gzip member closes — under the usual
    one-record-per-member layout that is exactly when each record completes.
    """

    def __init__(self) -> None:
        self._inner = WarcStreamParser()
        self._buf = b""
        self._comp_pos = 0
        self._d: zlib.decompressobj | None = None
        self._member_start = 0
        self._member_logical_base = 0
        self._member_records: list[RecordHandle] = []

    @property
    def logical_pos(self) -> int:
        return self._inner.logical_pos

    def feed(self, data: bytes | bytearray | memoryview) -> list[RecordHandle]:
        self._buf += bytes(data)
        out: list[RecordHandle] = []
        while self._buf:
            if self._d is None:
                if not self._buf.startswith(_GZIP_MAGIC):
                    raise GzipFormatError("bad gzip magic number")
                self._d = zlib.decompressobj(wbits=31)
                self._member_start = self._comp_pos
                self._member_logical_base = self._inner.logical_pos
                self._member_records = []

            chunk, self._buf = self._buf, b""
            try:
                decompressed = self._d.decompress(chunk)
            except zlib.error as exc:
                raise GzipFormatError(f"gzip decompression failed: {exc}") from exc

            self._member_records.extend(self._inner.feed(decompressed))
            self._comp_pos += len(chunk)

            if self._d.eof:
                unused = self._d.unused_data
                if unused:
                    self._comp_pos -= len(unused)
                try:
                    self._d.flush()
                except zlib.error as exc:
                    raise GzipFormatError(f"gzip member CRC error: {exc}") from exc
                length = self._comp_pos - self._member_start
                out.extend(self._patch(length, crc_ok=True))
                self._d = None
                if unused:
                    self._buf = unused + self._buf
        return out

    def finish(self) -> list[RecordHandle]:
        out: list[RecordHandle] = []
        if self._d is not None:
            # Open member at EOF means the compressed stream was cut short.
            try:
                tail = self._d.flush()
            except zlib.error as exc:
                raise GzipFormatError(f"gzip member CRC error: {exc}") from exc
            self._member_records.extend(self._inner.feed(tail))
            length = self._comp_pos - self._member_start + len(self._buf)
            self._comp_pos += len(self._buf)
            self._buf = b""
            self._inner.mark_truncated()
            salvaged = self._inner.finish()
            self._member_records.extend(salvaged)
            if not self._member_records:
                # Member ended inside the WARC header: synthesise a record so
                # the truncation is still visible to consumers.
                self._member_records.append(self._truncated_shell())
            out.extend(
                self._patch(length, crc_ok=False, extra=W_GZIP_TRUNCATED)
            )
            self._d = None
            return out
        if self._buf:
            raise GzipFormatError(
                f"{len(self._buf)} compressed bytes after final gzip member"
            )
        self._member_records = []
        out.extend(self._inner.finish())
        return out

    def _patch(
        self,
        length: int,
        crc_ok: bool,
        extra: str | None = None,
    ) -> list[RecordHandle]:
        patched: list[RecordHandle] = []
        for rec in self._member_records:
            warnings = list(rec.warnings)
            if extra:
                warnings.append(extra)
            patched.append(
                dataclasses.replace(
                    rec,
                    compressed_offset=self._member_start,
                    compressed_length=length,
                    member_logical_offset=self._member_logical_base,
                    gzip_crc_ok=crc_ok,
                    warnings=_dedup_warnings(warnings),
                )
            )
        self._member_records = []
        return patched

    def _truncated_shell(self) -> RecordHandle:
        """A placeholder handle for a member that ended mid-WARC-header."""
        import hashlib
        from datetime import datetime, timezone

        logical = self._inner.logical_pos
        token = hashlib.sha1(
            f"{self._member_start}:{logical}".encode()
        ).hexdigest()[:16]
        return RecordHandle(
            record_id=f"urn:warcarchive:truncated:offset-{self._member_start}:{token}",
            record_type=RecordType.UNKNOWN,
            target_uri=None,
            date=datetime.now(timezone.utc),
            payload_digest=None,
            block_digest=None,
            refers_to=None,
            profile=None,
            ip_address=None,
            truncated="length",
            warcinfo_id=None,
            http_status=None,
            http_head=b"",
            payload_offset=0,
            http_chunked=False,
            content_length=0,
            offset=logical,
            length=0,
            head_length=0,
            block_length=0,
            tail_length=0,
            warnings=(W_GZIP_TRUNCATED, W_RECORD_TRUNCATED),
        )


class RecordFeeder:
    """Feed WARC bytes in arbitrary chunks; auto-detects gzip compression.

    This is the low-level entry point behind :func:`read_stream`::

        feeder = RecordFeeder()
        for chunk in chunks:
            for record in feeder.feed(chunk): ...
        for record in feeder.finish(): ...
    """

    def __init__(self, compression: str = "auto") -> None:
        if compression not in ("auto", "gzip", "plain"):
            raise ValueError("compression must be one of auto/gzip/plain")
        self._compression = compression
        self._sniff = b""
        self._impl: WarcStreamParser | GzipWarcStreamParser | None = None

    def _select(self, head: bytes) -> None:
        if self._compression == "gzip" or (
            self._compression == "auto" and head.startswith(_GZIP_MAGIC)
        ):
            self._impl = GzipWarcStreamParser()
        else:
            self._impl = WarcStreamParser()

    def feed(self, data: bytes | bytearray | memoryview) -> list[RecordHandle]:
        if self._impl is None:
            self._sniff += bytes(data)
            if len(self._sniff) < 2:
                return []
            self._select(self._sniff)
            records = self._impl.feed(self._sniff)
            self._sniff = b""
            return records
        return self._impl.feed(data)

    def finish(self) -> list[RecordHandle]:
        if self._impl is None:
            self._select(self._sniff or b"\x00\x00")
            records = self._impl.feed(self._sniff)
            self._sniff = b""
            return records + self._impl.finish()
        return self._impl.finish()
