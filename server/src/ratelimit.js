// Fixed-window rate limiter, in-memory (plan §2.3, RULES #5).
// ponytail: per-process fixed window; move to Redis if the app runs multi-instance
// (plan §8 wants a stateless app server — this counter is the one bit of local state,
// acceptable for login/write ceilings; a shared store is the upgrade path).
const WINDOW_MS = 60_000;

export function createRateLimiter() {
  const hits = new Map(); // key -> { count, resetAt }

  // Returns { allowed, remaining, count }. `count` is the post-increment total so
  // callers can detect overflow (Phase 4 event coalescing needs the exact overage).
  function check(key, limit) {
    const now = Date.now();
    let e = hits.get(key);
    if (!e || now >= e.resetAt) {
      e = { count: 0, resetAt: now + WINDOW_MS };
      hits.set(key, e);
    }
    e.count += 1;
    return { allowed: e.count <= limit, remaining: Math.max(0, limit - e.count), count: e.count };
  }

  // Occasional sweep so idle keys don't accumulate. Called opportunistically.
  function gc() {
    const now = Date.now();
    for (const [k, e] of hits) if (now >= e.resetAt) hits.delete(k);
  }

  return { check, gc };
}
