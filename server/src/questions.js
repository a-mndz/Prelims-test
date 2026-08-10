// Question bank + participant-scoped serializer (plan §3, §3.1, §6, RULES #2).
// The bank is loaded once at boot (immutable during a run — freeze required before
// dry run per MEMORY.md). correct_option_id is stripped HERE, in one serializer, so
// no participant-scoped endpoint can leak it by forgetting to omit it (RULES #2).
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { seededShuffle } from "./shuffle.js";

const BANK_PATH = fileURLToPath(new URL("./questions.bank.json", import.meta.url));

// Seed loader. Validates shape at the trust boundary — a malformed bank must fail
// loudly at boot, never silently serve a broken/leaky question (not a lazy spot).
export function loadBank(path = BANK_PATH) {
  const raw = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(raw) || raw.length === 0) throw new Error("bank: empty or not an array");
  const ids = new Set();
  for (const q of raw) {
    if (typeof q.id !== "string" || !q.id) throw new Error("bank: question missing id");
    if (ids.has(q.id)) throw new Error(`bank: duplicate id ${q.id}`);
    ids.add(q.id);
    if (q.subject !== "C" && q.subject !== "PYTHON")
      throw new Error(`bank: ${q.id} bad subject ${q.subject}`);
    if (!Array.isArray(q.options) || q.options.length !== 4)
      throw new Error(`bank: ${q.id} must have exactly 4 options`);
    const optIds = new Set(q.options.map((o) => o.id));
    if (optIds.size !== 4) throw new Error(`bank: ${q.id} option ids not unique`);
    if (!optIds.has(q.correct_option_id))
      throw new Error(`bank: ${q.id} correct_option_id not among options`);
  }
  return raw;
}

export function createQuestionBank(bank = loadBank()) {
  const byId = new Map(bank.map((q) => [q.id, q]));

  // Strip correct_option_id (and analytics-only category) for participant scope.
  // Options are ORDER-SHUFFLED per (seed, question) — stable IDs are preserved, so
  // grading (matched on option_id, not position) is untouched (plan §3.1, RULES #2, #3).
  function serializeForParticipant(q, seed) {
    return {
      id: q.id,
      subject: q.subject,
      code_snippet: q.code_snippet ?? null,
      prompt: q.prompt,
      options: seededShuffle(
        q.options.map((o) => ({ id: o.id, text: o.text })),
        `${seed}:${q.id}`,
      ),
    };
  }

  return {
    size: bank.length,
    getById(id) {
      return byId.get(id) || null;
    },
    // Whole exam for one participant: questions ordered by seed, options shuffled,
    // answer key stripped. This is the ONLY path participant question data takes out.
    forParticipant(seed) {
      const ordered = seededShuffle(bank, `${seed}:order`);
      return ordered.map((q) => serializeForParticipant(q, seed));
    },
    // Grading path — one function, no per-type branch (RULES #3). Stable IDs only.
    isCorrect(questionId, optionId) {
      const q = byId.get(questionId);
      return !!q && q.correct_option_id === optionId;
    },
    // Score a whole session from stored responses. Position-independent: matches on
    // option_id, so the per-participant shuffle (§3.1) never touches the score. Counts any
    // row with a selected answer (answered=true) regardless of the flag — flagging a
    // question for review must never drop the earned answer (plan §4, orthogonal fields).
    grade(responses) {
      let correct = 0;
      for (const r of responses)
        if (r.answered && this.isCorrect(r.question_id, r.option_id)) correct += 1;
      return { correct, total: bank.length };
    },
  };
}
