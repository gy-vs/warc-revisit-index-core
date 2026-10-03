"""HTTP block handling: header splitting, chunked decoding, range readers.

A WARC ``response`` block for an HTTP target is the complete HTTP response
(message head + body).  The WARC *payload digest* hashes the HTTP *entity
body* (transfer-encoding removed), which is also what replay serves.
"""

from __future__ import annotations

import io

from .models import Headers

# Stream the body hash in fixed-size blocks to bound memory.
_HASH_CHUNK = 64 * 1024
# How much of an HTTP head we are willing to buffer.
_MAX_HEAD = 16 * 1024 * 1024

# HTTP status codes whose response never carries a body (RFC 9110 §6.4).
_NO_BODY_STATUSES = frozenset({204, 304})


def split_head(data: bytes) -> tuple[bytes, Headers, bytes] | None:
    """Split an HTTP message head from a byte buffer.

    Returns ``(status_line, headers, body)`` or ``None`` if the head
    terminator has not arrived yet.  Raises ValueError on an oversized head.
    """
    end, crlf = _find_head_end(data)
    if end is None:
        if len(data) > _MAX_HEAD:
            raise ValueError("HTTP header block exceeds maximum size")
        return None
    head = data[:end]
    body = data[end + len(crlf):]
    lines = head.split(crlf if crlf == b"\r\n" else b"\n")
    status_line = lines[0].rstrip(b"\r")
    headers = Headers()
    for raw_line in lines[1:]:
        line = raw_line.rstrip(b"\r")
        if not line.strip():
            continue
        name, _, value = line.partition(b":")
        headers.add(name.strip(), value.strip())
    return status_line, headers, body


def _find_head_end(data: bytes) -> tuple[int, bytes] | tuple[None, None]:
    for sep in (b"\r\n\r\n", b"\n\n", b"\r\r"):
        idx = data.find(sep)
        if idx >= 0:
            return idx, sep
    return None, None


def parse_status_line(line: bytes) -> tuple[int | None, str | None]:
    """Return ``(status_code, reason)`` from an HTTP status line."""
    parts = line.split(b" ", 2)
    if len(parts) < 2:
        return None, None
    try:
        status = int(parts[1])
    except ValueError:
        return None, None
    reason = parts[2].decode("iso-8859-1", "replace") if len(parts) > 2 else None
    return status, reason


def _is_http(warc_content_type: bytes | None, warc_target_uri: bytes | None) -> bool:
    ctype = (warc_content_type or b"").lower()
    if ctype.startswith(b"application/http"):
        return True
    if ctype:
        return False
    # No Content-Type: infer from the target URI scheme, as archives commonly
    # omit the type for HTTP responses.
    uri = (warc_target_uri or b"").lower()
    return uri.startswith(b"http://") or uri.startswith(b"https://")


# ---------------------------------------------------------------------------
# Streaming hashers fed with raw WARC block bytes
# ---------------------------------------------------------------------------

class PayloadHasher:
    """Incrementally extract the HTTP entity body (or raw block) and hash it.

    Feed raw record-block bytes to :meth:`update`; call :meth:`finish` at
    block end.  ``result`` afterwards holds the base32 digest, http status and
    whether the record block looked like HTTP at all.
    """

    def __init__(self, algorithm: str, is_http: bool) -> None:
        from ._util import new_hasher

        self.algorithm = algorithm
        self._hash = new_hasher(algorithm)
        self._is_http = is_http
        self._head_buf = bytearray()
        self._head_done = False
        self.http_status: int | None = None
        self.content_length: int | None = None
        self.chunked = False
        self._identity_left: int | None = None
        self._decoder: _ChunkedDecoder | None = None
        self.truncated = False
        self.trunc_reason: str | None = None
        self.warnings: list[str] = []
        self.body_bytes = 0

    def update(self, data: bytes) -> None:
        if not self._is_http or self._head_done:
            self._after_head(data)
            return
        self._head_buf.extend(data)
        end, sep = _find_head_end(bytes(self._head_buf))
        if end is None:
            if len(self._head_buf) > _MAX_HEAD:
                raise ValueError("HTTP header block exceeds maximum size")
            return
        head = bytes(self._head_buf[:end])
        rest = bytes(self._head_buf[end + len(sep):])
        self._head_buf.clear()
        self._configure_head(head)
        self._head_done = True
        self._after_head(rest)

    def finish(self) -> None:
        if not self._head_done:
            if self._is_http:
                # A completely empty block carries no HTTP message at all
                # (typical for revisit records); it is not a truncated head.
                if bytes(self._head_buf).strip():
                    self.truncated = True
                    self.trunc_reason = self.trunc_reason or "length"
                    self.warnings.append("incomplete HTTP header in record block")
                    self._hash.update(bytes(self._head_buf))
                    self.body_bytes += len(self._head_buf)
            else:
                self._hash.update(bytes(self._head_buf))
                self.body_bytes += len(self._head_buf)
            return
        if self._decoder is not None:
            tail = self._decoder.finish()
            if tail:
                self._hash.update(tail)
                self.body_bytes += len(tail)
            if self._decoder.truncated:
                self.truncated = True
                self.trunc_reason = self.trunc_reason or "length"
                self.warnings.append("truncated chunked HTTP body")
        elif (
            self.content_length is not None
            and (self._identity_left or 0) > 0
        ):
            self.truncated = True
            self.trunc_reason = self.trunc_reason or "length"
            self.warnings.append(
                f"HTTP body short: {self._identity_left} of "
                f"{self.content_length} declared bytes missing"
            )

    def digest(self) -> str:
        from ._util import b32encode

        return b32encode(self._hash.digest())

    # -- internals ----------------------------------------------------------

    def _configure_head(self, head: bytes) -> None:
        lines = head.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")
        if lines:
            self.http_status, _ = parse_status_line(lines[0])
        headers = Headers()
        for line in lines[1:]:
            if not line.strip():
                continue
            name, _, value = line.partition(b":")
            headers.add(name.strip(), value.strip())

        te = (headers.get("Transfer-Encoding") or b"").lower().replace(b" ", b"")
        # "chunked" may be the final TE coding among several.
        self.chunked = te.split(b",")[-1:] == [b"chunked"] if te else False
        cl = headers.get("Content-Length")
        if cl is not None and not self.chunked:
            try:
                self.content_length = int(cl.decode("ascii").strip())
            except ValueError:
                self.warnings.append(f"invalid HTTP Content-Length: {cl!r}")
                self.content_length = None

        status = self.http_status or 0
        if self.chunked:
            self._decoder = _ChunkedDecoder()
        elif self.content_length is not None:
            self._identity_left = self.content_length
        elif status < 200 or status in _NO_BODY_STATUSES:
            self._identity_left = 0
        else:
            # body runs to end of block / connection close
            self._identity_left = None

    def _after_head(self, data: bytes) -> None:
        if not data:
            return
        if self._decoder is not None:
            out = self._decoder.update(data)
        elif self._identity_left is None:
            out = data
        else:
            if self._identity_left < len(data):
                self.truncated = False  # extra bytes are padding, not truncation
                out = data[:self._identity_left]
            else:
                out = data
            self._identity_left -= len(out)
            if self._identity_left < 0:
                self._identity_left = 0
        if out:
            self._hash.update(out)
            self.body_bytes += len(out)


# ---------------------------------------------------------------------------
# Chunked transfer decoding (push style)
# ---------------------------------------------------------------------------

class _ChunkedDecoder:
    _SIZE = 0
    _DATA = 1
    _TRAILER = 2
    _DONE = 3

    def __init__(self) -> None:
        self._state = self._SIZE
        self._buf = bytearray()
        self._left = 0
        self.truncated = False

    def update(self, data: bytes) -> bytes:
        self._buf.extend(data)
        out = bytearray()
        while True:
            if self._state == self._SIZE:
                line = self._readline()
                if line is None:
                    break
                size_part = line.split(b";", 1)[0].strip()
                try:
                    self._left = int(size_part or b"0", 16)
                except ValueError:
                    # malformed chunk size: emit the rest verbatim and stop
                    out.extend(self._buf)
                    self._buf.clear()
                    self._state = self._DONE
                    self.truncated = True
                    break
                if self._left == 0:
                    self._state = self._TRAILER
                else:
                    self._state = self._DATA
            elif self._state == self._DATA:
                if self._left > 0:
                    take = min(len(self._buf), self._left)
                    out.extend(self._buf[:take])
                    del self._buf[:take]
                    self._left -= take
                    if self._left > 0:
                        break
                # chunk data done: expect CRLF
                if len(self._buf) < 2:
                    # tolerate bare LF
                    if self._buf and self._buf[0:1] == b"\n":
                        del self._buf[:1]
                        self._state = self._SIZE
                    break
                if bytes(self._buf[:2]) == b"\r\n":
                    del self._buf[:2]
                elif self._buf[0:1] == b"\n":
                    del self._buf[:1]
                self._state = self._SIZE
            elif self._state == self._TRAILER:
                line = self._readline()
                if line is None:
                    break
                if line.strip():
                    continue  # trailer field
                self._state = self._DONE
                self._buf.clear()
                break
            else:
                break
        return bytes(out)

    def finish(self) -> bytes:
        if self._state in (self._SIZE, self._DATA, self._TRAILER) and self._buf:
            self.truncated = True
            if self._state == self._DATA:
                out = bytes(self._buf)
                self._buf.clear()
                return out
        return b""

    def _readline(self) -> bytes | None:
        idx = self._buf.find(b"\n")
        if idx < 0:
            return None
        line = bytes(self._buf[:idx]).rstrip(b"\r")
        del self._buf[: idx + 1]
        return line


# ---------------------------------------------------------------------------
# File-backed body readers
# ---------------------------------------------------------------------------

class SpanReader(io.RawIOBase):
    """Read at most *length* bytes from an underlying binary file."""

    def __init__(self, fh, length: int) -> None:
        self._fh = fh
        self._left = length

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        if self._left <= 0:
            return 0
        n = self._fh.readinto(memoryview(b)[: min(len(b), self._left)])
        self._left -= n
        return n

    def readable_length(self) -> int:
        return self._left


class ChunkedBodyReader(io.RawIOBase):
    """Decode an HTTP/1.1 chunked body read from an underlying binary file."""

    def __init__(self, fh, limit: int | None = None) -> None:
        self._fh = fh
        self._limit = limit  # bytes of chunked framing still available
        self._buf = b""
        self._left = 0
        self._state = "size"
        self._eof = False
        self.truncated = False

    def readable(self) -> bool:
        return True

    def _read_source(self, n: int) -> bytes:
        if self._limit is not None:
            n = min(n, self._limit)
            if n <= 0:
                return b""
        data = self._fh.read(n)
        if self._limit is not None:
            self._limit -= len(data)
        return data

    def _readline(self) -> bytes | None:
        while b"\n" not in self._buf:
            b = self._read_source(1)
            if not b:
                return None
            self._buf += b
        idx = self._buf.find(b"\n")
        line = bytes(self._buf[:idx]).rstrip(b"\r")
        self._buf = self._buf[idx + 1:]
        return line

    def _fill(self) -> bool:
        """Advance the chunk state machine until decoded data is available."""
        while not self._eof:
            if self._state == "size":
                line = self._readline()
                if line is None:
                    return False
                size_part = line.split(b";", 1)[0].strip()
                try:
                    self._left = int(size_part or b"0", 16)
                except ValueError:
                    self.truncated = True
                    self._eof = True
                    return False
                if self._left == 0:
                    self._state = "trailer"
                else:
                    self._state = "data"
            elif self._state == "data":
                return True
            elif self._state == "trailer":
                line = self._readline()
                if line is None:
                    return False
                if not line.strip():
                    self._eof = True
            else:
                return False
        return False

    def readinto(self, b) -> int:
        out = memoryview(b)
        written = 0
        while written < len(b):
            if self._state == "data":
                want = min(len(b) - written, self._left)
                if self._limit is not None:
                    want = min(want, self._limit)
                if want <= 0 and self._limit == 0:
                    self.truncated = True
                    self._eof = True
                    break
                data = self._fh.read(want)
                if not data:
                    self.truncated = True
                    self._eof = True
                    break
                if self._limit is not None:
                    self._limit -= len(data)
                self._left -= len(data)
                out[written:written + len(data)] = data
                written += len(data)
                if self._left <= 0:
                    crlf = self._read_source(2)
                    if crlf == b"\n":
                        pass
                    elif crlf != b"\r\n":
                        if crlf == b"":
                            self.truncated = True
                            self._eof = True
                            break
                    self._state = "size"
                continue
            if not self._fill():
                break
        return written


def open_http_body(fh, headers: Headers, status: int, block_left: int):
    """Wrap *fh* (positioned at the HTTP body) in a bounded raw reader.

    Returns a raw binary stream yielding the decoded entity body (chunked
    framing removed).  The stream never reads past *block_left* bytes of the
    WARC record block.  Callers that want buffering wrap it in
    ``io.BufferedReader`` themselves.
    """
    te = (headers.get("Transfer-Encoding") or b"").lower().replace(b" ", b"")
    if te.split(b",")[-1:] == [b"chunked"]:
        return ChunkedBodyReader(fh, block_left)
    cl = headers.get("Content-Length")
    if cl is not None:
        try:
            length = int(cl.decode("ascii").strip())
        except ValueError:
            length = block_left
        length = min(length, block_left)
        return SpanReader(fh, length)
    if status < 200 or status in _NO_BODY_STATUSES:
        return SpanReader(fh, 0)
    return SpanReader(fh, block_left)
