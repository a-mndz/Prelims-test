// Dev seed — creates one participant + one admin from env-supplied passwords.
// ponytail: dev convenience only; prod seeding goes through a migration + secrets store.
import { hashPassword } from "./crypto.js";
import { createStore } from "./store.js";

export function seedStore(store = createStore()) {
  store.addParticipant({
    username: process.env.SEED_PARTICIPANT_USER || "participant1",
    passwordHash: hashPassword(process.env.SEED_PARTICIPANT_PASS || "change-me-participant"),
    competitionId: "prelim",
  });
  store.addAdmin({
    username: process.env.SEED_ADMIN_USER || "admin1",
    passwordHash: hashPassword(process.env.SEED_ADMIN_PASS || "change-me-admin"),
  });
  return store;
}
