// Deterministic per-participant shuffle (plan §3.1). Order is derived from a
// server-stored seed on every fetch — never stored client-side, never trusted from
// the client. Same seed => same order, so a refresh or session recovery is stable.
// ponytail: mulberry32 PRNG + Fisher-Yates; no dependency, deterministic across
// Node versions (plain 32-bit int math, not Math.random). Reproducibility is the
// whole point here, so a hand-rolled seeded PRNG is correct, not lazy.

// FNV-1a over a string -> 32-bit unsigned seed. Combines the exam seed with a salt
// (the question id) so each question's option order is independent yet reproducible.
function seed32(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

function mulberry32(a) {
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Return a new array shuffled deterministically from `seedStr`. Does not mutate input.
export function seededShuffle(items, seedStr) {
  const rng = mulberry32(seed32(seedStr));
  const out = items.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}
