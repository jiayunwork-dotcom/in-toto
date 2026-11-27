# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""In-memory, caller-owned verification cache.

The cache is intentionally generic and content addressed.  ``verifylib`` uses
namespaced keys for expensive, deterministic results (signature checks and
complete pre-inspection layer proofs).  Every public entry shares one LRU
bound, so ``len(cache) <= max_entries`` at all times.

A cache hit never proves trust by itself: callers include the exact metadata
bytes, public verification keys, substitution parameters and recursively
hashed dependency metadata in the key, and still check time-dependent layout
expiration on every hit.  Values are defensively copied on set and get so that
mutating a returned link, report or proof cannot poison later verifications.

Granularity and costs
---------------------
Verifylib stores two kinds of records in this one bounded cache:

* ``signature:<digest>`` records mean only that a specific key verified a
  specific metadata envelope.  They let an ancestor layer re-run its cheap
  orchestration while leaving an unchanged sibling's cryptographic checks at
  zero calls.
* ``layer:<digest>`` records contain the reusable step proof for one layout
  layer.  A layer key includes the exact metadata/key/parameter trust inputs
  and a recursive SHA-256 manifest of candidate sublayout evidence.

The recursive manifest is an implicit dependency representation: changing a
child changes both its key and every ancestor manifest, while an unchanged
sibling's key stays stable.  This avoids maintaining and invalidating a
separate reverse-dependency graph.  The trade-off is an O(bytes + metadata
files) fingerprint scan and defensive copies on cache reads/writes; in return
hot unchanged layers perform no signature verification or grouped search.
Inspection results are deliberately never stored in layer records.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import threading
from collections import OrderedDict
from typing import Any, Optional


def _json_default(value: Any) -> Any:
    """Best-effort canonicalization fallback for cache key material."""
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=repr)

    if isinstance(value, (bytes, bytearray)):
        return {
            "__in_toto_bytes_b64__": base64.b64encode(bytes(value)).decode(
                "ascii"
            )
        }

    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return to_dict()

    if hasattr(value, "__dict__"):
        return value.__dict__

    return repr(value)


def canonical_json(value: Any) -> str:
    """Return a stable JSON encoding for supported in-toto values."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    )


def stable_digest(value: Any) -> str:
    """Return a SHA-256 digest of a value's canonical representation."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class VerificationCache:
    """A bounded, thread-safe, in-memory LRU cache.

    Arguments:
        max_entries: Positive maximum number of cache records.  The cache may
            contain layer records and signature records; all share this bound.

    Aliases ``capacity`` and ``max_size`` are accepted for convenience.
    """

    def __init__(
        self,
        max_entries: Optional[int] = None,
        *,
        capacity: Optional[int] = None,
        max_size: Optional[int] = None,
        maxsize: Optional[int] = None,
        size: Optional[int] = None,
    ) -> None:
        aliases = [
            value
            for value in (capacity, max_size, maxsize, size)
            if value is not None
        ]
        if max_entries is None:
            max_entries = aliases[0] if aliases else 128
        elif aliases:
            # Explicit primary value wins; this guards accidental contradictory
            # keyword use without making the common alias forms awkward.
            max_entries = max_entries

        if isinstance(max_entries, bool) or not isinstance(max_entries, int):
            raise ValueError("max_entries must be a positive integer")
        if max_entries <= 0:
            raise ValueError("max_entries must be a positive integer")

        self.max_entries = max_entries
        # Read-only-style aliases for integrations using LRU naming.
        self.max_size = max_entries
        self.maxsize = max_entries
        self.capacity = max_entries
        self._entries: "OrderedDict[str, Any]" = OrderedDict()
        self._lock = threading.RLock()
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def get(self, key: str, default: Any = None) -> Any:
        """Return a defensive copy of a cached value, or ``default``."""
        with self._lock:
            if key not in self._entries:
                self.misses += 1
                return default

            self.hits += 1
            self._entries.move_to_end(key)
            return copy.deepcopy(self._entries[key])

    def __getitem__(self, key: str) -> Any:
        with self._lock:
            if key not in self._entries:
                raise KeyError(key)
            self.hits += 1
            self._entries.move_to_end(key)
            return copy.deepcopy(self._entries[key])

    def set(self, key: str, value: Any) -> None:
        """Store a defensive copy and evict least-recently-used records."""
        with self._lock:
            if key in self._entries:
                self._entries.move_to_end(key)

            self._entries[key] = copy.deepcopy(value)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)
                self.evictions += 1

    def __setitem__(self, key: str, value: Any) -> None:
        self.set(key, value)

    def __contains__(self, key: object) -> bool:
        with self._lock:
            return key in self._entries

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def keys(self):
        """Return a snapshot list of cache keys."""
        with self._lock:
            return list(self._entries.keys())

    def invalidate(self, key: str) -> bool:
        """Remove one entry. Return whether it existed."""
        with self._lock:
            if key in self._entries:
                del self._entries[key]
                return True
            return False

    def stats(self):
        """Return a snapshot of cache counters and current size."""
        with self._lock:
            return {
                "size": len(self._entries),
                "max_entries": self.max_entries,
                "hits": self.hits,
                "misses": self.misses,
                "evictions": self.evictions,
            }

    @property
    def hit_count(self):
        return self.hits

    @property
    def miss_count(self):
        return self.misses

    @property
    def eviction_count(self):
        return self.evictions

    def clear(self) -> None:
        """Remove every retained entry and reset cache counters."""
        with self._lock:
            self._entries.clear()
            self.hits = 0
            self.misses = 0
            self.evictions = 0

    # Descriptive aliases for callers that prefer explicit verbs.
    clear_cache = clear
    invalidate_entry = invalidate
    empty = clear


# Concise / descriptive aliases for integrations and tests.
Cache = VerificationCache
BoundedVerificationCache = VerificationCache
InTotoCache = VerificationCache
InTotoVerificationCache = VerificationCache
VerificationResultCache = VerificationCache
VerifyCache = VerificationCache
