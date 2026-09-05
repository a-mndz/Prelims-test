// Regression suite for "a participant created through the admin portal is not saved".
//
// Two independent causes, both covered here:
//   1. No connection string ever reached the deployment, so the bootstrap fell back to the
//      in-memory store. That store lives in one process's heap, so on Vercel each cold or
//      concurrent lambda instance starts empty: the POST returned 201, the portal said
//      "Created", and the row was gone on the next request.
//   2. Nothing applied schema.sql. Even with a connection string, the first INSERT against
//      a fresh Supabase database fails with 42P01 "relation does not exist".
//
// Everything below runs without a database: the pool is injected.
import { test } from "node:test";
import assert from "node:assert/strict";

import { resolveStoreMode, StoreConfigError } from "../src/bootstrap.js";
import { SCHEMA_SQL, ensureSchema, createPgStore } from "../src/pgStore.js";
import { seedStore } from "../src/seed.js";
import { createStore } from "../src/store.js";

// A pool double that records how it was constructed and every statement it was given.
function recordingPools() {
  const configs = [];
  const statements = [];
  const factory = (cfg) => {
    configs.push(cfg);
    return {
      async query(sql) {
        statements.push(sql);
        return { rows: [], rowCount: 0 };
      },
      async end() {},
    };
  };
  return { configs, statements, factory };
}

const DEPLOYED_ENVS = [
  { VERCEL: "1" },
  { NODE_ENV: "production" },
  { VERCEL: "1", NODE_ENV: "production", VERCEL_ENV: "production" },
];

test("a deployed environment with no connection string refuses to serve from the volatile store", () => {
  for (const env of DEPLOYED_ENVS) {
    assert.throws(
      () => resolveStoreMode(env),
      (err) => {
        assert.ok(err instanceof StoreConfigError, `${JSON.stringify(env)} must be a config error`);
        assert.equal(err.code, "store_not_configured");
        // The message has to name the fix; this is the failure an operator will see.
        assert.match(err.message, /DATABASE_URL|POSTGRES_URL/);
        return true;
      },
      `expected ${JSON.stringify(env)} to refuse the in-memory fallback`
    );
  }
});

test("local development still gets the in-memory store", () => {
  assert.deepEqual(resolveStoreMode({}), { mode: "memory" });
  assert.deepEqual(resolveStoreMode({ NODE_ENV: "development" }), { mode: "memory" });
});

test("DATABASE_URL wins; POSTGRES_URL is the Supabase-integration fallback", () => {
  const both = resolveStoreMode({
    VERCEL: "1",
    DATABASE_URL: "postgres://self-managed/db",
    POSTGRES_URL: "postgres://supabase-pooler/db",
  });
  assert.equal(both.mode, "postgres");
  assert.equal(both.url, "postgres://self-managed/db");

  const supabaseOnly = resolveStoreMode({ VERCEL: "1", POSTGRES_URL: "postgres://supabase-pooler/db" });
  assert.equal(supabaseOnly.url, "postgres://supabase-pooler/db");
});

test("the non-pooled Supabase URL is kept separately for DDL, and never duplicated", () => {
  const both = resolveStoreMode({
    VERCEL: "1",
    POSTGRES_URL: "postgres://pooler.supabase.com:6543/postgres",
    POSTGRES_URL_NON_POOLING: "postgres://db.supabase.co:5432/postgres",
  });
  assert.equal(both.url, "postgres://pooler.supabase.com:6543/postgres");
  assert.equal(both.directUrl, "postgres://db.supabase.co:5432/postgres");

  // With only the direct URL there is nothing to prefer for DDL: the same connection
  // would otherwise be opened twice on every cold start.
  const directOnly = resolveStoreMode({
    VERCEL: "1",
    POSTGRES_URL_NON_POOLING: "postgres://db.supabase.co:5432/postgres",
  });
  assert.equal(directOnly.url, "postgres://db.supabase.co:5432/postgres");
  assert.equal(directOnly.directUrl, null);
});

test("every DDL statement in schema.sql is idempotent, so it can run on every cold start", () => {
  const sql = SCHEMA_SQL.split("\n")
    .map((line) => line.replace(/--.*$/, ""))
    .join("\n");

  assert.deepEqual(sql.match(/CREATE\s+TABLE\s+(?!IF\s+NOT\s+EXISTS)/gi) || [], []);
  assert.deepEqual(sql.match(/CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?!IF\s+NOT\s+EXISTS)/gi) || [], []);

  // CREATE TYPE has no IF NOT EXISTS form; the DO block swallowing duplicate_object is the
  // only idempotent spelling.
  assert.match(sql, /DO\s+\$\$[\s\S]*CREATE\s+TYPE\s+exam_status[\s\S]*duplicate_object[\s\S]*END\s+\$\$/i);

  // Every table the store writes to must actually be created.
  for (const table of ["participants", "admins", "violations", "exam_sessions", "results", "responses"]) {
    assert.match(sql, new RegExp(`CREATE\\s+TABLE\\s+IF\\s+NOT\\s+EXISTS\\s+${table}\\b`, "i"));
  }

  // The coalescing upsert in pgStore names this exact partial index as its conflict target.
  assert.match(sql, /CREATE\s+UNIQUE\s+INDEX\s+IF\s+NOT\s+EXISTS\s+violations_coalesced_uniq/i);
});

test("ensureSchema hands the whole script to the client in one batch", async () => {
  const seen = [];
  await ensureSchema({
    async query(sql) {
      seen.push(sql);
      return { rows: [] };
    },
  });
  assert.deepEqual(seen, [SCHEMA_SQL]);
});

test("the schema is applied once per process, before the store is used", async () => {
  const pools = recordingPools();
  const store = createPgStore("postgres://user:pw@host:5432/db", { poolFactory: pools.factory });

  await store.init();
  await store.init();
  await store.init();

  assert.deepEqual(pools.statements, [SCHEMA_SQL], "schema must be applied exactly once");
});

test("a failed bootstrap is retried on the next request, not cached forever", async () => {
  let attempts = 0;
  const store = createPgStore("postgres://user:pw@host:5432/db", {
    poolFactory: () => ({
      async query() {
        attempts += 1;
        throw new Error("ECONNREFUSED");
      },
      async end() {},
    }),
  });

  // A paused Supabase project must not poison a warm instance until the next deploy.
  await assert.rejects(store.init(), /ECONNREFUSED/);
  await assert.rejects(store.init(), /ECONNREFUSED/);
  assert.equal(attempts, 2);
});

test("DDL prefers the direct connection and releases it again", async () => {
  const pools = recordingPools();
  const store = createPgStore("postgres://pooler.supabase.com:6543/postgres", {
    directConnectionString: "postgres://db.supabase.co:5432/postgres",
    poolFactory: pools.factory,
  });

  await store.init();

  assert.equal(pools.configs.length, 2, "the runtime pool plus a short-lived DDL pool");
  assert.match(pools.configs[0].connectionString, /pooler\.supabase\.com:6543/);
  assert.match(pools.configs[1].connectionString, /db\.supabase\.co:5432/);
  assert.equal(pools.configs[1].max, 1, "the DDL pool exists for one statement batch");
  assert.deepEqual(pools.statements, [SCHEMA_SQL]);
});

test("sslmode is stripped from the URL and translated into the ssl option Supabase needs", () => {
  const tls = recordingPools();
  createPgStore("postgres://user:pw@db.supabase.co:5432/postgres?sslmode=require", {
    poolFactory: tls.factory,
  });
  assert.ok(!tls.configs[0].connectionString.includes("sslmode"), "node-postgres ignores sslmode");
  assert.deepEqual(tls.configs[0].ssl, { rejectUnauthorized: false });

  const plain = recordingPools();
  createPgStore("postgres://user:pw@localhost:5432/db?sslmode=disable", { poolFactory: plain.factory });
  assert.equal(plain.configs[0].ssl, false, "an explicit opt-out must stay off for local sockets");
});

test("a deployed environment must not fall back to the published default admin credentials", async () => {
  await assert.rejects(seedStore(createStore(), { VERCEL: "1" }), /SEED_ADMIN_USER/);
  await assert.rejects(
    seedStore(createStore(), { NODE_ENV: "production", SEED_ADMIN_USER: "ops" }),
    /SEED_ADMIN_PASS/
  );
});

test("a deployed environment seeds the admin but not the demo participant", async () => {
  const store = await seedStore(createStore(), {
    VERCEL: "1",
    SEED_ADMIN_USER: "ops",
    SEED_ADMIN_PASS: "a-real-admin-password",
  });

  assert.ok(await store.getAdminByUsername("ops"));
  assert.equal(await store.getAdminByUsername("admin1"), null);
  // Participants come from the admin portal in a deployed environment.
  assert.equal(await store.getParticipantByUsername("participant1"), null);
});

test("dev and test keep the documented default seeds the other suites log in with", async () => {
  const store = await seedStore(createStore(), {});
  assert.ok(await store.getParticipantByUsername("participant1"));
  assert.ok(await store.getAdminByUsername("admin1"));
});
