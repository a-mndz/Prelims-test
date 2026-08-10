// Password hashing + JWT — Node stdlib only (RULES #9, ponytail rung 3/6).
// competition-system-plan-v2.md §2, §2.1
import {
  scryptSync,
  scrypt,
  randomBytes,
  timingSafeEqual,
  createHmac,
} from "node:crypto";
import { promisify } from "node:util";

const scryptAsync = promisify(scrypt);

// --- Password hashing -------------------------------------------------------
// ponytail: plan §2 names "bcrypt/argon2"; scrypt is the stdlib member of the same
// memory-hard KDF family, so no dependency is added. Swap to argon2 only if a policy
// requires that specific algorithm. Format: scrypt$N$salt$hash (all hex).
const SCRYPT_N = 16384; // CPU/memory cost

export function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 32, { N: SCRYPT_N });
  return `scrypt$${SCRYPT_N}$${salt.toString("hex")}$${hash.toString("hex")}`;
}

export function verifyPassword(password, stored) {
  const parts = String(stored).split("$");
  if (parts.length !== 4 || parts[0] !== "scrypt") return false;
  const N = Number.parseInt(parts[1], 10);
  const salt = Buffer.from(parts[2], "hex");
  const expected = Buffer.from(parts[3], "hex");
  const actual = scryptSync(password, salt, expected.length, { N });
  // Constant-time compare — guard against length mismatch which timingSafeEqual throws on.
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

// Async twin of verifyPassword — scrypt runs on libuv's threadpool instead of blocking the
// event loop (~28ms/attempt synchronously). At a login stampede (150 participants at the
// window open) the sync version serializes into seconds of blocked CPU, stalling autosave,
// /health, and the sweep. Login handlers are async, so they use this. Same format/semantics.
export async function verifyPasswordAsync(password, stored) {
  const parts = String(stored).split("$");
  if (parts.length !== 4 || parts[0] !== "scrypt") return false;
  const N = Number.parseInt(parts[1], 10);
  const salt = Buffer.from(parts[2], "hex");
  const expected = Buffer.from(parts[3], "hex");
  const actual = await scryptAsync(password, salt, expected.length, { N });
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

// A real scrypt hash of a random secret, computed once at boot. Login handlers verify the
// submitted password against THIS when the username is unknown, so a missing account costs
// the same scrypt work as a present one — closing the timing oracle that would otherwise let
// an attacker enumerate valid usernames (fast 401 = no such user, slow 401 = wrong password).
export const DUMMY_PASSWORD_HASH = hashPassword(randomBytes(32).toString("hex"));

// --- JWT (HS256) ------------------------------------------------------------
// A JWT is header.payload.signature, base64url, HMAC-SHA256 signed. Role claim is
// set here server-side at issuance and never read from the client (RULES #1, plan §2).
function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function b64urlJson(obj) {
  return b64url(JSON.stringify(obj));
}

function sign(data, secret) {
  return b64url(createHmac("sha256", secret).update(data).digest());
}

export function signJwt(claims, secret, ttlSec) {
  const now = Math.floor(Date.now() / 1000);
  const payload = { ...claims, iat: now, exp: now + ttlSec };
  const head = b64urlJson({ alg: "HS256", typ: "JWT" });
  const body = b64urlJson(payload);
  const sig = sign(`${head}.${body}`, secret);
  return `${head}.${body}.${sig}`;
}

// Returns the claims object, or null on any failure (bad shape, bad signature, expired).
// Signature verified in constant time before the payload is trusted.
export function verifyJwt(token, secret) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [head, body, sig] = parts;
  const expected = sign(`${head}.${body}`, secret);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, "base64").toString("utf8"));
  } catch {
    return null;
  }
  if (payload.alg) return null; // alg lives in header only; ignore any in-payload spoof
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp < now) return null;
  return payload;
}

export function newSessionId() {
  return randomBytes(18).toString("hex");
}
