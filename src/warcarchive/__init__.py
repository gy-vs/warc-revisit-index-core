"""warcarchive — streaming WARC reader with a persistent replay index.

Typical use::

    from warcarchive import Index, Query, validate

    index = Index.create("replay.db")
    index.add_source("crawl-2026.warc.gz")
    index.close()

    # later, possibly in another process
    index = Index.open("replay.db")
    for capture in index.query(Query(uri="https://example.com/")):
        result = capture.resolve()        # follows revisit links
        print(result.origin_record_id, len(result.body))

The package has no third-party runtime dependencies and never needs a
network service.
"""

from __future__ import annotations

from .digest import Digest, DigestHasher, normalize_digest, parse_digest
from .errors import (
    DigestError,
    DigestMismatchError,
    DuplicateRecordIdError,
    GzipFormatError,
    IndexConsistencyError,
    IndexError_,
    InvalidRecordTypeError,
    RecordNotFoundError,
    RevisitDigestMismatchError,
    RevisitError,
    RevisitProfileError,
    RevisitTargetNotFoundError,
    RevisitTruncatedError,
    SourceNotFoundError,
    StorageError,
    TruncatedRecordError,
    UnknownDigestError,
    WarcError,
    WarcFormatError,
)
from .index import Index, PayloadResult, Query, RecordView
from .model import (
    RecordHandle,
    RecordType,
    WarcHead,
)
from .parser import (
    GzipWarcStreamParser,
    RecordFeeder,
    WarcStreamParser,
)
from .reader import parse_bytes, read_file, read_stream
from .validate import (
    ValidationIssue,
    ValidationReport,
    iter_issues,
    validate,
)

__all__ = [
    # entry points
    "Index",
    "Query",
    "RecordView",
    "PayloadResult",
    "RecordFeeder",
    "WarcStreamParser",
    "GzipWarcStreamParser",
    "read_file",
    "read_stream",
    "parse_bytes",
    "validate",
    "iter_issues",
    "ValidationReport",
    "ValidationIssue",
    # model
    "RecordHandle",
    "RecordType",
    "WarcHead",
    "Digest",
    "DigestHasher",
    "parse_digest",
    "normalize_digest",
    # errors
    "WarcError",
    "WarcFormatError",
    "GzipFormatError",
    "DigestError",
    "DigestMismatchError",
    "UnknownDigestError",
    "StorageError",
    "SourceNotFoundError",
    "TruncatedRecordError",
    "IndexError_",
    "RecordNotFoundError",
    "DuplicateRecordIdError",
    "IndexConsistencyError",
    "RevisitError",
    "RevisitTargetNotFoundError",
    "RevisitDigestMismatchError",
    "RevisitProfileError",
    "RevisitTruncatedError",
    "InvalidRecordTypeError",
]

__version__ = "0.1.0"
