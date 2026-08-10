// Auth middleware — role enforcement + session exclusivity + CSRF (RULES #1, #5).
// competition-system-plan-v2.md §1, §2.1, §2.2
import { config } from "./config.js";
import { verifyJwt } from "./crypto.js";
import { parseCookies, sendJson } from "./http.js";

const STATE_CHANGING = new Set(["POST", "PATCH", "PUT", "DELETE"]);

// Verify the cookie JWT and return its claims, or null. The role claim was set
// server-side at issuance; a forged/expired-secret token fails signature check
// in verifyJwt and returns null (plan §7: forged-JWT rejection).
export function authenticate(req) {
  const cookies = parseCookies(req);
  const token = cookies[config.cookie.name];
  return verifyJwt(token, config.jwtSecret); // null on missing/bad/expired
}

// CSRF belt-and-suspenders (plan §2.1): every state-changing request must carry the
// custom header, which a cross-site form cannot set. SameSite=Strict is primary.
export function csrfOk(req) {
  if (!STATE_CHANGING.has(req.method)) return true;
  return req.headers[config.csrfHeader] !== undefined;
}

// Guard for /api/admin/* — role must be exactly "admin" (RULES #1) AND the token's
// session id must match the row's active_session_id (FIX M2: admin tokens are revocable
// exactly like participant tokens — logout/re-login invalidates every prior token).
export function requireAdmin(req, res, store) {
  const claims = authenticate(req);
  if (!claims || claims.role !== "admin") {
    sendJson(res, 403, { error: "forbidden" });
    return null;
  }
  if (!store.adminSessionMatches(claims.sub, claims.sid)) {
    sendJson(res, 401, { error: "session_superseded" });
    return null;
  }
  return claims;
}

// Guard for /api/exam/* — role must be participant AND the token's session id must
// match the row's active_session_id (single active session, plan §2.2). A taken-over
// session returns 401 so the old browser knows it was displaced.
export function requireParticipant(req, res, store) {
  const claims = authenticate(req);
  if (!claims || claims.role !== "participant") {
    sendJson(res, 403, { error: "forbidden" });
    return null;
  }
  if (!store.sessionMatches(claims.sub, claims.sid)) {
    sendJson(res, 401, { error: "session_superseded" });
    return null;
  }
  return claims;
}
