import { hashPassword } from "./crypto.js";
import { createStore } from "./store.js";

export async function seedStore(store = createStore()) {
  await store.addParticipant({
    username: process.env.SEED_PARTICIPANT_USER || "participant1",
    passwordHash: hashPassword(process.env.SEED_PARTICIPANT_PASS || "change-me-participant"),
    competitionId: "prelim",
  });
  await store.addAdmin({
    username: process.env.SEED_ADMIN_USER || "admin1",
    passwordHash: hashPassword(process.env.SEED_ADMIN_PASS || "change-me-admin"),
  });
  return store;
}
