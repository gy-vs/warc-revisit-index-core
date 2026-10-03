"""Exception hierarchy for warcarchive.

All errors raised by the library derive from :class:`WarcError`, so callers
can catch the whole family.  More specific branches let replay services react
differently to corrupt bytes, missing storage, broken revisit links and index
problems.
"""

from __future__ import annotations


class WarcError(Exception):
    """Base class for every error raised by this package."""


# --- Parsing -------------------------------------------------------------


class WarcFormatError(WarcError):
    """The WARC byte stream violates the format in a non-recoverable way."""


class GzipFormatError(WarcFormatError):
    """A per-record gzip member is corrupt or cannot be decoded."""


# --- Digest handling -----------------------------------------------------


class DigestError(WarcError):
    """Base class for payload/block digest failures."""


class DigestMismatchError(DigestError):
    """A computed digest does not match the value declared by the record."""

    def __init__(self, declared: str, computed: str) -> None:
        self.declared = declared
        self.computed = computed
        super().__init__(
            f"digest mismatch: declared={declared} computed={computed}"
        )


class UnknownDigestError(DigestError):
    """The digest algorithm/encoding is not recognised."""


# --- Storage / IO --------------------------------------------------------


class StorageError(WarcError):
    """Base class for problems reading record bytes from the original file."""


class SourceNotFoundError(StorageError):
    """A WARC file referenced by the index cannot be opened."""

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"WARC source not found: {path!r}")


class TruncatedRecordError(StorageError):
    """The stored offsets run past the file or the gzip member is short."""


# --- Index ---------------------------------------------------------------


class IndexError_(WarcError):
    """Base class for index problems (avoids shadowing builtins.IndexError)."""


class RecordNotFoundError(IndexError_):
    """No record matches the supplied locator (id / uri+date / digest)."""


class DuplicateRecordIdError(IndexError_):
    """Two records in the same index claim the same WARC-Record-ID."""


class IndexConsistencyError(IndexError_):
    """Persisted index data is internally inconsistent or unreadable."""


# --- Revisit resolution --------------------------------------------------


class RevisitError(WarcError):
    """Base class for failures while resolving a revisit record."""


class RevisitTargetNotFoundError(RevisitError):
    """The record a revisit points at (or its URI+digest match) is missing."""


class RevisitDigestMismatchError(RevisitError):
    """The candidate original record's payload digest does not match.

    This is distinct from :class:`DigestMismatchError`: that one describes a
    record failing its own declared digest; this one describes the *link*
    between a revisit and its original being inconsistent.
    """

    def __init__(self, expected: str, actual: str, record_id: str | None = None) -> None:
        self.expected = expected
        self.actual = actual
        self.record_id = record_id
        msg = (
            f"revisit payload digest mismatch: expected={expected} actual={actual}"
        )
        if record_id:
            msg += f" candidate={record_id}"
        super().__init__(msg)


class RevisitProfileError(RevisitError):
    """The revisit profile is unknown or required linking headers are absent."""


class RevisitTruncatedError(RevisitError):
    """The revisit or the original it resolves to is marked truncated."""


class InvalidRecordTypeError(WarcError):
    """An operation was asked about a record type it cannot handle."""
