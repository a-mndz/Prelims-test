// Auth middleware — role enforcement + session exclusivity + CSRF (RULES #1, #5).
// competition-system-plan-v2.md §1, §2.1, §2.2
import { config } from "./config.js";
import { verifyJwt } from "./crypto.js";
import { parseCookies, sendJson } from "./http.js";

const STATE_CHANGING = new Set(["POST", "PATCH", "PUT", "DELETE"]);

export function authenticate(req) {
  const cookies = parseCookies(req);
  const token = cookies[config.cookie.name];
  return verifyJwt(token, config.jwtSecret); // null on missing/bad/expired
}

export function csrfOk(req) {
  if (!STATE_CHANGING.has(req.method)) return true;
  return req.headers[config.csrfHeader] !== undefined;
}

export async function requireAdmin(req, res, store) {
  const claims = authenticate(req);
  if (!claims || claims.role !== "admin") {
    sendJson(res, 403, { error: "forbidden" });
    return null;
  }
  const match = await store.adminSessionMatches(claims.sub, claims.sid);
  if (!match) {
    sendJson(res, 401, { error: "session_superseded" });
    return null;
  }
  return claims;
}

export async function requireParticipant(req, res, store) {
  const claims = authenticate(req);
  if (!claims || claims.role !== "participant") {
    sendJson(res, 403, { error: "forbidden" });
    return null;
  }
  const match = await store.sessionMatches(claims.sub, claims.sid);
  if (!match) {
    sendJson(res, 401, { error: "session_superseded" });
    return null;
  }
  return claims;
}
