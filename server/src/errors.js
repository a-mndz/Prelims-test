// One error type for "the environment is set up wrong" — an operator mistake with a known
// fix, as opposed to a bug or an outage. Entry points use it to answer 503 + the fix-it
// message instead of an opaque 500.
//
// This module deliberately imports nothing. It is the only part of the config chain that
// cannot itself throw while loading, which is what lets api/index.js import it statically
// and still classify a failure that happened while config.js was being evaluated.

export const CONFIG_ERROR_CODES = new Set([
  "config_error",
  "env_not_configured", //   a required env var is missing or malformed (config.js, seed.js)
  "store_not_configured", // no durable Postgres URL in a deployed environment (bootstrap.js)
]);

export class ConfigError extends Error {
  constructor(message, code = "config_error") {
    super(message);
    this.name = "ConfigError";
    this.code = code;
  }
}

// Matches on `code`, not `instanceof`. A serverless bundler can hand two callers separate
// copies of this module, and `instanceof` silently returns false across that boundary —
// which would downgrade a legible 503 back to the anonymous 500 this exists to prevent.
export function isConfigError(err) {
  return typeof err?.code === "string" && CONFIG_ERROR_CODES.has(err.code);
}
