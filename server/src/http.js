// Tiny HTTP helpers over node:http — no framework (RULES #9, ponytail rung 3).
import { config } from "./config.js";
import { readFileSync, existsSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { normalize, join, extname } from "node:path";

export function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    // Defense-in-depth headers; cheap and standard.
    "x-content-type-options": "nosniff",
    "cache-control": "no-store",
  });
  res.end(payload);
}

export function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    // A malformed percent-escape in an attacker-controlled cookie must not throw a 500
    // (decodeURIComponent throws URIError on e.g. "%zz"). Fall back to the raw value.
    if (k) {
      try {
        out[k] = decodeURIComponent(v);
      } catch {
        out[k] = v;
      }
    }
  }
  return out;
}

// Set the session cookie with the mandated posture (plan §2.1): httpOnly, Secure,
// SameSite=Strict. maxAge scopes it to the token lifetime.
export function setSessionCookie(res, token, maxAgeSec) {
  const c = config.cookie;
  const attrs = [
    `${c.name}=${encodeURIComponent(token)}`,
    `Path=${c.path}`,
    `Max-Age=${maxAgeSec}`,
    `SameSite=${c.sameSite}`,
  ];
  if (c.httpOnly) attrs.push("HttpOnly");
  if (c.secure) attrs.push("Secure");
  res.setHeader("Set-Cookie", attrs.join("; "));
}

export function clearSessionCookie(res) {
  const c = config.cookie;
  const attrs = [`${c.name}=`, `Path=${c.path}`, "Max-Age=0", `SameSite=${c.sameSite}`];
  if (c.httpOnly) attrs.push("HttpOnly");
  if (c.secure) attrs.push("Secure");
  res.setHeader("Set-Cookie", attrs.join("; "));
}

// Read + JSON-parse a request body with a hard size cap (input validation at the
// trust boundary — not a place to be lazy). Rejects oversized or malformed bodies.
export function readJsonBody(req, maxBytes = 16 * 1024) {
  return new Promise((resolve) => {
    let size = 0;
    const chunks = [];
    let aborted = false;
    req.on("data", (chunk) => {
      if (aborted) return;
      size += chunk.length;
      if (size > maxBytes) {
        aborted = true;
        // FIX L4: pause, don't destroy. destroy() here killed the socket before the
        // caller's 400 could flush, so oversized bodies saw a connection reset instead
        // of {error:"body_too_large"}. Pausing stops the inflow (bounded memory) and
        // lets the 400 go out; Node then closes the connection itself after the
        // response flushes, because the request body was never fully consumed.
        req.pause();
        resolve({ error: "body_too_large" });
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (aborted) return;
      if (chunks.length === 0) return resolve({ value: {} });
      try {
        resolve({ value: JSON.parse(Buffer.concat(chunks).toString("utf8")) });
      } catch {
        resolve({ error: "invalid_json" });
      }
    });
    req.on("error", () => !aborted && resolve({ error: "read_error" }));
  });
}

export function clientIp(req) {
  // Behind a reverse proxy (prod TLS termination, plan §8) the socket address is the
  // proxy's, so every participant shares one IP and per-IP limits/lockout collapse onto
  // the whole cohort. When config.trustProxyHops > 0 we read X-Forwarded-For, taking the
  // entry that many hops from the RIGHT — the proxy appends the real client, so rightmost
  // entries are trusted; leftmost are client-supplied and spoofable. hops=0 trusts only
  // the socket (never trust raw XFF — that's exactly how you spoof past a per-IP limit).
  const socketIp = req.socket.remoteAddress || "unknown";
  const hops = config.trustProxyHops;
  if (hops > 0) {
    const xff = req.headers["x-forwarded-for"];
    if (typeof xff === "string" && xff.length) {
      const chain = xff.split(",").map((s) => s.trim()).filter(Boolean);
      const idx = chain.length - hops;
      if (idx >= 0 && chain[idx]) return chain[idx];
    }
  }
  return socketIp;
}

// Mobile detection for the desktop-only start gate (plan §5.1). UA-only and deliberately
// spoofable — accepted per §5.1 (fairness-by-default, not a perimeter). Viewport/touch
// heuristics live client-side; this is the server's authoritative half of the check.
// ponytail: one regex over the common mobile UA tokens; widen the list if real-device
// testing (Phase 4 on-device task) surfaces a browser this misses.
const MOBILE_UA = /Android|iPhone|iPad|iPod|IEMobile|BlackBerry|Opera Mini|Mobile|webOS/i;
export function isMobileUserAgent(ua) {
  return typeof ua === "string" && MOBILE_UA.test(ua);
}

// Static file serving for the participant shell + deterrent assets (frontend decision:
// static HTML/CSS/vanilla JS served by the same Node server, DECISIONS.md). Returns true
// if it served the request, false if the path is not a public asset (caller falls through).
const PUBLIC_DIR = fileURLToPath(new URL("../public/", import.meta.url));
const MIME = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript" };
export function serveStatic(req, res, urlPath) {
  if (req.method !== "GET") return false;
  // "/" serves the participant exam shell (public/exam.html — the only page there today).
  const rel = urlPath === "/" ? "exam.html" : urlPath.replace(/^\/+/, "");
  // Path-traversal guard: resolve under PUBLIC_DIR and confirm the result stays inside it
  // (input validation at the trust boundary — never a lazy spot). ../ escapes are rejected.
  const full = normalize(join(PUBLIC_DIR, rel));
  if (!full.startsWith(PUBLIC_DIR)) return false;
  if (!existsSync(full) || !statSync(full).isFile()) return false;
  const type = MIME[extname(full)] || "application/octet-stream";
  const body = readFileSync(full);
  res.writeHead(200, {
    "content-type": `${type}; charset=utf-8`,
    "content-length": body.length,
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "content-security-policy": "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
  });
  res.end(body);
  return true;
}
