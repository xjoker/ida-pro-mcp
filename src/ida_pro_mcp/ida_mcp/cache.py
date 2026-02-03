"""LRU Cache implementation for IDA Pro MCP Server.

Provides thread-safe caching with TTL expiration for frequently accessed data
such as function lookups, decompilation results, and cross-references.
"""

import threading
import time
from collections import OrderedDict
from typing import Callable, Generic, Optional, TypeVar

T = TypeVar("T")


class LRUCache(Generic[T]):
    """Thread-safe LRU cache with TTL expiration.

    Features:
    - Automatic eviction of least recently used items when max_size is reached
    - Time-based expiration (TTL) for cached entries
    - Thread-safe operations using RLock
    - Optional key generation function for complex keys
    """

    def __init__(self, max_size: int = 1000, ttl_seconds: float = 300.0):
        """Initialize the LRU cache.

        Args:
            max_size: Maximum number of entries to store
            ttl_seconds: Time-to-live for entries in seconds (0 = no expiration)
        """
        self.max_size = max_size
        self.ttl = ttl_seconds
        self._cache: OrderedDict[str, tuple[T, float]] = OrderedDict()
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Optional[T]:
        """Get a value from the cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None

            value, timestamp = entry

            # Check TTL expiration
            if self.ttl > 0 and time.monotonic() - timestamp > self.ttl:
                del self._cache[key]
                self._misses += 1
                return None

            # Move to end (most recently used)
            self._cache.move_to_end(key)
            self._hits += 1
            return value

    def set(self, key: str, value: T) -> None:
        """Set a value in the cache.

        Args:
            key: Cache key
            value: Value to cache
        """
        with self._lock:
            # Remove old entry if exists
            if key in self._cache:
                del self._cache[key]

            # Evict LRU entries if at capacity
            while len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)

            # Add new entry
            self._cache[key] = (value, time.monotonic())

    def invalidate(self, key: Optional[str] = None) -> None:
        """Invalidate cache entries.

        Args:
            key: Specific key to invalidate, or None to clear all
        """
        with self._lock:
            if key is None:
                self._cache.clear()
            elif key in self._cache:
                del self._cache[key]

    def invalidate_prefix(self, prefix: str) -> int:
        """Invalidate all entries with keys starting with prefix.

        Args:
            prefix: Key prefix to match

        Returns:
            Number of entries invalidated
        """
        with self._lock:
            keys_to_remove = [k for k in self._cache if k.startswith(prefix)]
            for key in keys_to_remove:
                del self._cache[key]
            return len(keys_to_remove)

    def get_or_compute(
        self,
        key: str,
        compute_fn: Callable[[], T],
        ttl_override: Optional[float] = None,
    ) -> T:
        """Get from cache or compute and cache the value.

        Args:
            key: Cache key
            compute_fn: Function to compute value if not cached
            ttl_override: Optional TTL override for this entry

        Returns:
            Cached or computed value
        """
        # Try to get from cache first
        value = self.get(key)
        if value is not None:
            return value

        # Compute value
        value = compute_fn()

        # Store with optional TTL override
        if ttl_override is not None:
            original_ttl = self.ttl
            self.ttl = ttl_override
            self.set(key, value)
            self.ttl = original_ttl
        else:
            self.set(key, value)

        return value

    def stats(self) -> dict:
        """Get cache statistics.

        Returns:
            Dict with hits, misses, size, and hit_rate
        """
        with self._lock:
            total = self._hits + self._misses
            return {
                "hits": self._hits,
                "misses": self._misses,
                "size": len(self._cache),
                "max_size": self.max_size,
                "hit_rate": self._hits / total if total > 0 else 0.0,
            }

    def clear_stats(self) -> None:
        """Reset cache statistics."""
        with self._lock:
            self._hits = 0
            self._misses = 0


# ============================================================================
# Global Cache Instances
# ============================================================================

# Function lookup cache: name/address -> function info
# High TTL since function metadata rarely changes
function_cache = LRUCache(max_size=5000, ttl_seconds=300.0)

# Decompilation cache: address -> pseudocode
# Moderate size, longer TTL since decompilation is expensive
decompile_cache = LRUCache(max_size=200, ttl_seconds=600.0)

# Cross-reference cache: address -> xrefs list
# Moderate size and TTL
xrefs_cache = LRUCache(max_size=2000, ttl_seconds=300.0)

# String cache: regex pattern -> matches
# Smaller size, moderate TTL
string_cache = LRUCache(max_size=500, ttl_seconds=180.0)


def invalidate_all_caches() -> None:
    """Invalidate all global caches.

    Call this when IDB changes significantly (e.g., new analysis, database reload).
    """
    function_cache.invalidate()
    decompile_cache.invalidate()
    xrefs_cache.invalidate()
    string_cache.invalidate()


def invalidate_function_caches(addr: Optional[int] = None) -> None:
    """Invalidate caches related to a specific function.

    Args:
        addr: Function address to invalidate, or None for all functions
    """
    if addr is None:
        function_cache.invalidate()
        decompile_cache.invalidate()
        xrefs_cache.invalidate()
    else:
        # Invalidate specific function entries
        addr_hex = hex(addr)
        function_cache.invalidate(addr_hex)
        decompile_cache.invalidate(addr_hex)
        xrefs_cache.invalidate_prefix(addr_hex)


def get_cache_stats() -> dict:
    """Get statistics for all caches.

    Returns:
        Dict with stats for each cache type
    """
    return {
        "function_cache": function_cache.stats(),
        "decompile_cache": decompile_cache.stats(),
        "xrefs_cache": xrefs_cache.stats(),
        "string_cache": string_cache.stats(),
    }
