(function () {
  "use strict";

  const state = {
    role: null,
    activeAuthRole: "participant",
    questions: [],
    currentIndex: 0,
    answers: {},
    flags: {},
    examState: "NOT_STARTED",
    startedAt: null,
    durationSec: 3600,
    timerInterval: null,
    saveQueue: Promise.resolve(),
    pendingSaves: 0,
    failedSaves: new Map(),
    submitting: false,
    clockOffsetMs: 0,
    leaderboard: [],
  };

  async function apiFetch(endpoint, options = {}) {
    const headers = { "x-requested-with": "XMLHttpRequest", ...(options.headers || {}) };
    let body = options.body;
    if (body && typeof body === "object") {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(body);
    }
    const response = await fetch(endpoint, { ...options, headers, body, credentials: "same-origin" });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(payload.message || payload.error || `HTTP ${response.status}`);
      error.code = payload.error;
      error.status = response.status;
      throw error;
    }
    return payload;
  }

  function showView(viewId, focus = true) {
    document.querySelectorAll(".view-section").forEach((view) => view.classList.add("hidden"));
    const target = document.getElementById(viewId);
    if (!target) return;
    target.classList.remove("hidden");
    if (focus) {
      const heading = target.querySelector("h1, h2");
      if (heading) {
        heading.tabIndex = -1;
        heading.focus({ preventScroll: true });
      }
    }
  }

  function showAlert(containerId, message) {
    const alert = document.getElementById(containerId);
    if (!alert) return;
    alert.textContent = message || "";
    alert.classList.toggle("hidden", !message);
  }

  function setButtonBusy(button, busy, busyText) {
    if (!button.dataset.label) button.dataset.label = button.textContent;
    button.disabled = busy;
    button.textContent = busy ? busyText : button.dataset.label;
  }

  function setSaveStatus(message, isError = false) {
    const status = document.getElementById("save-status");
    // Announce failures only: per-answer "Saving..."/"All changes saved" chatter
    // means 150+ screen-reader interruptions across a 50-question session.
    status.setAttribute("aria-live", isError ? "polite" : "off");
    status.textContent = message || "";
    status.classList.toggle("hidden", !message);
    status.classList.toggle("error", isError);
  }

  function setAuthenticatedRole(role) {
    state.role = role;
    document.getElementById("user-role-badge").textContent = role === "admin" ? "Administrator" : "Participant";
    document.getElementById("logout-btn").classList.remove("hidden");
  }

  function formatDuration(seconds) {
    if (!Number.isFinite(seconds)) return "--";
    if (seconds % 3600 === 0) return `${seconds / 3600} ${seconds === 3600 ? "hour" : "hours"}`;
    return `${Math.ceil(seconds / 60)} minutes`;
  }

  function updateStartFacts(total, durationSec) {
    document.getElementById("start-total").textContent = Number.isFinite(total) ? total : "--";
    document.getElementById("start-duration").textContent = formatDuration(durationSec);
  }

  function switchTab(role) {
    state.activeAuthRole = role;
    document.querySelectorAll(".tab-button").forEach((button) => {
      const active = button.dataset.role === role;
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", active);
    });
    // Keep the typed username; only the stale password is cleared on role switch.
    document.getElementById("login-password").value = "";
    document.getElementById("login-username").focus();
    showAlert("auth-alert", null);
  }

  // Fullscreen is a DETERRENT (RULES #8): a participant can Esc out any time — the
  // fullscreen_exit beacon in anticheat.js is the signal the server thresholds.
  // requestFullscreen needs a user gesture, so this runs inside the login-submit and
  // start-click handlers. Best-effort: a denial must never block the exam itself.
  function enterFullscreen() {
    document.documentElement.requestFullscreen?.().catch(() => {});
  }

  async function handleLogin(event) {
    event.preventDefault();
    const button = document.getElementById("login-button");
    const username = document.getElementById("login-username").value.trim();
    const password = document.getElementById("login-password").value;
    const endpoint = state.activeAuthRole === "participant"
      ? "/api/auth/participant/login"
      : "/api/auth/admin/login";

    // Request fullscreen BEFORE the await — the user-gesture context does not survive
    // the network round-trip in all browsers. Participants only; admins review freely.
    if (state.activeAuthRole === "participant") enterFullscreen();

    showAlert("auth-alert", null);
    setButtonBusy(button, true, "Signing in...");
    try {
      const session = await apiFetch(endpoint, { method: "POST", body: { username, password } });
      setAuthenticatedRole(session.role);
      if (session.role === "participant") await initParticipantSession();
      else await initAdminDashboard();
    } catch (error) {
      const message = error.code === "invalid_credentials"
        ? "Username or password is incorrect."
        : error.code === "rate_limited"
          ? "Too many attempts. Wait briefly, then try again."
          : `Sign-in failed: ${error.message}`;
      showAlert("auth-alert", message);
    } finally {
      setButtonBusy(button, false);
    }
  }

  async function handleLogout() {
    const button = document.getElementById("logout-btn");
    setButtonBusy(button, true, "Logging out...");
    try {
      await apiFetch("/api/auth/logout", { method: "POST" });
      location.reload();
    } catch (error) {
      setSaveStatus(`Logout failed: ${error.message}`, true);
      setButtonBusy(button, false);
    }
  }

  async function restoreSession() {
    try {
      const session = await apiFetch("/api/auth/session");
      setAuthenticatedRole(session.role);
      if (session.role === "participant") await initParticipantSession();
      else await initAdminDashboard();
    } catch (error) {
      showView("view-auth", false);
      if (error.status !== 401) showAlert("auth-alert", `Session check failed: ${error.message}`);
    }
  }

  function setClockOffset(serverNow) {
    // Display-only correction: a fast local clock would otherwise hit zero and
    // auto-submit before the server's authoritative deadline (server clock is truth).
    if (Number.isFinite(serverNow)) state.clockOffsetMs = serverNow - Date.now();
  }

  async function initParticipantSession() {
    const status = await apiFetch("/api/exam/status");
    state.examState = status.status;
    state.durationSec = status.durationSec || state.durationSec;
    setClockOffset(status.serverNow);
    updateStartFacts(status.total, state.durationSec);

    if (status.status === "NOT_STARTED") {
      showView("view-start");
      return;
    }
    if (status.status === "IN_PROGRESS") {
      state.startedAt = status.startedAt;
      try {
        await loadQuestions(true);
      } catch (error) {
        // Refresh into an expired-but-unswept session: status still says IN_PROGRESS but
        // reads are already 403 exam_expired. Terminal for the participant — the sweep
        // will grade the autosaved answers — so show the submitted view, not a dead end.
        if (error.code === "exam_expired") {
          showSubmittedView("expired");
          return;
        }
        throw error;
      }
      startTimer();
      showView("view-exam");
      return;
    }
    showSubmittedView();
  }

  async function startExam() {
    const button = document.getElementById("start-button");
    showAlert("start-alert", null);
    setButtonBusy(button, true, "Starting...");
    // Re-request here too: fullscreen from login is lost if the participant lingered
    // on the start screen and pressed Esc, or resumed a session in a fresh tab.
    enterFullscreen();
    try {
      const startedExam = await apiFetch("/api/exam/start", { method: "POST" });
      state.startedAt = startedExam.startedAt;
      state.durationSec = startedExam.durationSec;
      state.examState = "IN_PROGRESS";
      setClockOffset(startedExam.serverNow);
      updateStartFacts(startedExam.total, startedExam.durationSec);
      await loadQuestions(false);
      startTimer();
      showView("view-exam");
    } catch (error) {
      const message = error.code === "mobile_not_allowed"
        ? error.message
        : `Could not start exam: ${error.message}`;
      showAlert("start-alert", message);
    } finally {
      setButtonBusy(button, false);
    }
  }

  async function loadQuestions(resume) {
    const requests = [apiFetch("/api/exam/questions")];
    if (resume) requests.push(apiFetch("/api/exam/review"));
    const [questionData, review] = await Promise.all(requests);
    state.questions = questionData.questions || [];
    state.currentIndex = 0;
    state.answers = {};
    state.flags = {};
    if (review) {
      review.responses.forEach((response) => {
        if (response.optionId) state.answers[response.questionId] = response.optionId;
        if (response.flagged) state.flags[response.questionId] = true;
      });
    }
    renderQuestion();
    renderGrid();
  }

  function renderQuestion() {
    const question = state.questions[state.currentIndex];
    if (!question) return;

    document.getElementById("q-subject").textContent = question.subject === "PYTHON" ? "Python" : question.subject;
    document.getElementById("q-number").textContent = `Question ${state.currentIndex + 1} of ${state.questions.length}`;
    document.getElementById("q-prompt").textContent = question.prompt;

    const codeBlock = document.getElementById("q-code");
    codeBlock.querySelector("code").textContent = question.code_snippet || "";
    codeBlock.classList.toggle("hidden", !question.code_snippet);

    const options = document.getElementById("options-list");
    options.replaceChildren(options.querySelector("legend"));
    const selected = state.answers[question.id];
    question.options.forEach((option, index) => {
      const label = document.createElement("label");
      label.className = `option-item${selected === option.id ? " selected" : ""}`;

      const radio = document.createElement("input");
      radio.type = "radio";
      radio.name = `question-${question.id}`;
      radio.value = option.id;
      radio.className = "option-radio";
      radio.checked = selected === option.id;
      radio.addEventListener("change", () => selectOption(question.id, option.id));

      const copy = document.createElement("span");
      copy.className = "option-copy";
      copy.textContent = option.text;
      copy.setAttribute("data-option", String.fromCharCode(65 + index));

      label.append(radio, copy);
      options.appendChild(label);
    });

    const flagButton = document.getElementById("flag-btn");
    const flagged = !!state.flags[question.id];
    flagButton.setAttribute("aria-pressed", flagged);
    flagButton.textContent = flagged ? "Flagged for review" : "Flag for review";
    document.getElementById("btn-prev").disabled = state.currentIndex === 0;
    document.getElementById("btn-next").disabled = state.currentIndex === state.questions.length - 1;
  }

  function queueSave(questionId) {
    const payload = {
      questionId,
      optionId: state.answers[questionId] || null,
      flagged: !!state.flags[questionId],
    };
    state.pendingSaves += 1;
    setSaveStatus("Saving...");

    const request = state.saveQueue.then(() => apiFetch("/api/exam/answer", { method: "PATCH", body: payload }));
    state.saveQueue = request
      .then(() => {
        state.failedSaves.delete(questionId);
      })
      .catch((error) => {
        state.failedSaves.set(questionId, payload);
        throw error;
      })
      .finally(() => {
        state.pendingSaves -= 1;
        if (state.failedSaves.size) setSaveStatus("Answer not saved", true);
        else if (state.pendingSaves === 0) setSaveStatus("All changes saved");
        if (state.examState === "IN_PROGRESS") renderGrid();
      });
    state.saveQueue = state.saveQueue.catch(() => {});
    return request;
  }

  function selectOption(questionId, optionId) {
    state.answers[questionId] = optionId;
    // Update in place: rebuilding the radio group here would remove the focused
    // radio from the DOM and eject keyboard/screen-reader users on every arrow press.
    document.querySelectorAll("#options-list .option-item").forEach((label) => {
      const radio = label.querySelector(".option-radio");
      const selected = radio.value === optionId;
      radio.checked = selected;
      label.classList.toggle("selected", selected);
    });
    renderGrid();
    queueSave(questionId).catch(() => {});
  }

  function toggleFlag() {
    const question = state.questions[state.currentIndex];
    if (!question) return;
    state.flags[question.id] = !state.flags[question.id];
    renderQuestion();
    renderGrid();
    queueSave(question.id).catch(() => {});
  }

  function renderGrid() {
    const grid = document.getElementById("question-grid");
    grid.replaceChildren();
    state.questions.forEach((question, index) => {
      const answered = !!state.answers[question.id];
      const flagged = !!state.flags[question.id];
      const current = index === state.currentIndex;
      const unsynced = state.failedSaves.has(question.id);
      const button = document.createElement("button");
      button.type = "button";
      button.className = `grid-node${answered ? " answered" : ""}${flagged ? " flagged" : ""}${current ? " current" : ""}${unsynced ? " unsynced" : ""}`;
      button.textContent = index + 1;
      button.setAttribute("aria-label", `Question ${index + 1}, ${answered ? "answered" : "unanswered"}${flagged ? ", flagged" : ""}${unsynced ? ", not saved" : ""}`);
      if (current) button.setAttribute("aria-current", "step");
      button.addEventListener("click", () => navigateTo(index));
      grid.appendChild(button);
    });

    const answered = Object.keys(state.answers).length;
    document.getElementById("stat-answered").textContent = `${answered} of ${state.questions.length} answered`;
  }

  function navigateTo(index) {
    if (index < 0 || index >= state.questions.length) return;
    state.currentIndex = index;
    renderQuestion();
    renderGrid();
    document.getElementById("q-prompt").focus({ preventScroll: true });
  }

  function normalizeStartTime(startedAt) {
    if (typeof startedAt === "number") return startedAt;
    const parsed = Date.parse(startedAt);
    return Number.isFinite(parsed) ? parsed : null;
  }

  function startTimer() {
    clearInterval(state.timerInterval);
    const timerBox = document.getElementById("timer-box");
    const timer = document.getElementById("timer-display");
    const announcer = document.getElementById("timer-announce");
    const startedAt = normalizeStartTime(state.startedAt);
    // Milestone announcements for screen-reader users — the visual urgent state is
    // color-only, so without these a blind candidate gets no low-time warning at all.
    const milestones = new Set([1800, 900, 300, 60]);
    timerBox.classList.remove("hidden");

    const update = () => {
      if (!startedAt) {
        timer.textContent = "--:--";
        setSaveStatus("Timer unavailable. Server timing still applies.", true);
        return;
      }
      const elapsed = Math.floor((Date.now() + state.clockOffsetMs - startedAt) / 1000);
      const remaining = Math.max(0, state.durationSec - elapsed);
      const minutes = Math.floor(remaining / 60).toString().padStart(2, "0");
      const seconds = (remaining % 60).toString().padStart(2, "0");
      timer.textContent = `${minutes}:${seconds}`;
      timerBox.classList.toggle("urgent", remaining <= 300);
      if (milestones.has(remaining)) {
        milestones.delete(remaining);
        announcer.textContent = `${remaining / 60} minute${remaining === 60 ? "" : "s"} remaining`;
      }
      if (remaining === 0) {
        clearInterval(state.timerInterval);
        submitExam(true);
      }
    };

    update();
    state.timerInterval = setInterval(update, 1000);
  }

  function openSubmitDialog() {
    const total = state.questions.length;
    const answered = Object.keys(state.answers).length;
    document.getElementById("modal-answered").textContent = answered;
    document.getElementById("modal-unanswered").textContent = total - answered;
    document.getElementById("modal-flagged").textContent = Object.values(state.flags).filter(Boolean).length;
    showAlert("submit-alert", null);
    document.getElementById("submit-modal").showModal();
  }

  async function flushFailedSaves() {
    await state.saveQueue;
    const failedQuestions = [...state.failedSaves.keys()];
    if (!failedQuestions.length) return;
    await Promise.all(failedQuestions.map((questionId) => queueSave(questionId).catch(() => {})));
    await state.saveQueue;
    if (state.failedSaves.size) throw new Error("Some answers could not be saved. Check your connection and try again.");
  }

  async function submitExam(automatic = false) {
    if (state.submitting) return;
    state.submitting = true;
    const button = document.getElementById("confirm-submit-button");
    setButtonBusy(button, true, automatic ? "Time ended" : "Submitting...");
    showAlert("submit-alert", null);
    try {
      await flushFailedSaves();
      await apiFetch("/api/exam/submit", { method: "POST" });
      showSubmittedView(automatic ? "timeout" : undefined);
    } catch (error) {
      if (error.code === "already_submitted" || error.code === "exam_not_in_progress") {
        showSubmittedView(automatic ? "timeout" : undefined);
      } else {
        const message = `Submission failed: ${error.message}`;
        if (automatic && !document.getElementById("submit-modal").open) openSubmitDialog();
        showAlert("submit-alert", message);
        setSaveStatus(message, true);
      }
    } finally {
      state.submitting = false;
      setButtonBusy(button, false);
    }
  }

  const SUBMITTED_NOTES = {
    violation: "Your exam was submitted by the server after repeated rule violations were recorded (leaving the exam window, exiting fullscreen, or using copy/paste). If you believe this was in error, contact the administrator.",
    timeout: "Time expired. All answers saved during the exam were submitted automatically.",
    expired: "Your exam time ended. Answers saved during the session are recorded and will be graded.",
  };

  function showSubmittedView(cause) {
    state.examState = "SUBMITTED";
    clearInterval(state.timerInterval);
    document.getElementById("timer-box").classList.add("hidden");
    document.getElementById("save-status").classList.add("hidden");
    const noteEl = document.getElementById("submitted-note");
    if (!noteEl.dataset.base) noteEl.dataset.base = noteEl.textContent;
    let text = SUBMITTED_NOTES[cause] || noteEl.dataset.base;
    // Only known when this tab ran the exam; on a fresh resume of an already
    // submitted attempt there is no local answer state to count.
    if (state.questions.length) {
      const answered = Object.keys(state.answers).length;
      text += ` ${answered} of ${state.questions.length} answers were recorded.`;
    }
    noteEl.textContent = text;
    const dialog = document.getElementById("submit-modal");
    if (dialog.open) dialog.close();
    showView("view-submitted");
  }

  async function initAdminDashboard() {
    showView("view-admin");
    // Sequential: violations table resolves usernames from the leaderboard cache.
    await loadLeaderboard();
    await loadViolations();
  }

  function appendCell(row, value, className) {
    const cell = document.createElement("td");
    if (className) {
      const span = document.createElement("span");
      span.className = className;
      span.textContent = value;
      cell.appendChild(span);
    } else {
      cell.textContent = value;
    }
    row.appendChild(cell);
  }

  async function loadLeaderboard() {
    try {
      const data = await apiFetch("/api/admin/leaderboard");
      // Cache the server (score) order: rank is pinned to it, so re-sorting the
      // display by name/status never renumbers anyone.
      state.leaderboard = data.leaderboard || [];
      renderLeaderboard();
    } catch (error) {
      setSaveStatus(`Could not load leaderboard: ${error.message}`, true);
    }
  }

  function renderLeaderboard() {
    const body = document.getElementById("leaderboard-tbody");
    body.replaceChildren();
    if (!state.leaderboard.length) {
      const row = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = 6;
      cell.className = "empty-cell";
      cell.textContent = "No participants are registered for this round.";
      row.appendChild(cell);
      body.appendChild(row);
      return;
    }
    // Rank comes from the server's score order regardless of display sort.
    const ranks = new Map(state.leaderboard.map((entry, index) => [entry.participant_id, index + 1]));
    const sortKey = document.getElementById("leaderboard-sort").value;
    const rows = [...state.leaderboard];
    if (sortKey === "name") rows.sort((a, b) => a.username.localeCompare(b.username));
    else if (sortKey === "status") {
      rows.sort((a, b) => a.status.localeCompare(b.status) || a.username.localeCompare(b.username));
    }
    rows.forEach((entry) => {
      const row = document.createElement("tr");
      // Rank only means something once a score exists; ungraded rows get a dash.
      appendCell(row, entry.correct === null ? "-" : String(ranks.get(entry.participant_id)), "rank-cell");
      appendCell(row, entry.username);
      appendCell(row, entry.correct === null ? "Not graded" : `${entry.correct} / ${entry.total}`, "score-cell");
      appendCell(row, entry.status.replace(/_/g, " ").toLowerCase());
      appendCell(row, entry.submitted_by || "-");
      appendCell(
        row,
        entry.malpractice ? `Malpractice (${entry.strikes})` : "Clean",
        entry.malpractice ? "badge badge-danger" : "badge badge-clean",
      );
      body.appendChild(row);
    });
  }

  const MAX_CREATE_ROWS = 10;

  function addCreateUserRow() {
    const rows = document.getElementById("create-user-rows");
    if (rows.children.length >= MAX_CREATE_ROWS) return;
    const row = document.createElement("div");
    row.className = "create-user-row";
    const n = rows.children.length + 1;
    [["username", "text"], ["password", "text"]].forEach(([field, type]) => {
      const input = document.createElement("input");
      input.type = type;
      input.className = "form-input";
      input.autocomplete = "off";
      input.dataset.field = field;
      input.placeholder = `${field.charAt(0).toUpperCase()}${field.slice(1)} ${n}`;
      // Only the first row is required; extra rows may be left blank.
      if (n === 1) input.required = true;
      row.appendChild(input);
    });
    rows.appendChild(row);
    document.getElementById("add-user-row").disabled = rows.children.length >= MAX_CREATE_ROWS;
  }

  function resetCreateUserRows() {
    document.getElementById("create-user-rows").replaceChildren();
    document.getElementById("add-user-row").disabled = false;
    addCreateUserRow();
  }

  async function handleCreateUser(event) {
    event.preventDefault();
    const button = document.getElementById("create-user-button");
    // Collect filled rows; skip fully-empty ones. A row with only one field filled is an error.
    const rows = [...document.querySelectorAll("#create-user-rows .create-user-row")];
    const entries = [];
    for (const row of rows) {
      const username = row.querySelector('[data-field="username"]').value.trim();
      const password = row.querySelector('[data-field="password"]').value;
      if (!username && !password) continue;
      if (!username || !password) {
        showAlert("create-user-alert", "Each filled row needs both a username and a password.");
        return;
      }
      entries.push({ username, password });
    }
    if (!entries.length) {
      showAlert("create-user-alert", "Enter at least one username and password.");
      return;
    }
    const names = entries.map((e) => e.username);
    if (new Set(names).size !== names.length) {
      showAlert("create-user-alert", "Duplicate usernames in the form.");
      return;
    }
    showAlert("create-user-alert", null);
    setButtonBusy(button, true, "Creating...");
    // Sequential POSTs to the existing single-create endpoint; report per-row failures.
    const created = [];
    const failed = [];
    for (const entry of entries) {
      try {
        const result = await apiFetch("/api/admin/participants", {
          method: "POST",
          body: entry,
        });
        created.push(result.username);
      } catch (error) {
        const reason = error.code === "duplicate_username" ? "username taken" : error.message;
        failed.push(`${entry.username} (${reason})`);
      }
    }
    setButtonBusy(button, false);
    if (created.length) {
      setSaveStatus(`Created ${created.length} participant${created.length > 1 ? "s" : ""}: ${created.join(", ")}.`);
      await loadLeaderboard();
    }
    if (failed.length) {
      showAlert("create-user-alert", `Not created: ${failed.join("; ")}.`);
    } else {
      resetCreateUserRows();
    }
  }

  async function loadViolations() {
    const button = document.getElementById("refresh-violations");
    setButtonBusy(button, true, "Refreshing...");
    try {
      const violationLog = await apiFetch("/api/admin/violations");
      const body = document.getElementById("violations-tbody");
      body.replaceChildren();
      if (!violationLog.violations?.length) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.colSpan = 4;
        cell.className = "empty-cell";
        cell.textContent = "No violation signals have been recorded.";
        row.appendChild(cell);
        body.appendChild(row);
        return;
      }
      // One row per participant, not per event: at 50 concurrent participants the
      // per-event feed is unreadable. Roll up into strikes + compact type summary.
      const byParticipant = new Map();
      violationLog.violations.forEach((v) => {
        let entry = byParticipant.get(v.participant_id);
        if (!entry) {
          entry = { strikes: 0, types: new Map(), last: v.created_at };
          byParticipant.set(v.participant_id, entry);
        }
        const count = v.count || 1;
        entry.strikes += count;
        entry.types.set(v.type, (entry.types.get(v.type) || 0) + count);
        if (v.created_at > entry.last) entry.last = v.created_at;
      });
      // Username lookup from the leaderboard cache (loaded before violations).
      const names = new Map(state.leaderboard.map((e) => [e.participant_id, e.username]));
      // Worst offenders first.
      const rows = [...byParticipant.entries()].sort((a, b) => b[1].strikes - a[1].strikes);
      rows.forEach(([participantId, entry]) => {
        const row = document.createElement("tr");
        appendCell(row, names.get(participantId) || `#${participantId}`);
        appendCell(row, entry.strikes, entry.strikes >= 3 ? "badge badge-danger" : "badge");
        appendCell(
          row,
          [...entry.types.entries()]
            .map(([type, n]) => `${type.replace(/_/g, " ")} ×${n}`)
            .join(", "),
        );
        appendCell(row, new Date(entry.last).toLocaleString());
        body.appendChild(row);
      });
    } catch (error) {
      setSaveStatus(`Could not load violations: ${error.message}`, true);
    } finally {
      setButtonBusy(button, false);
    }
  }

  async function reconcileStatus() {
    if (state.role !== "participant" || state.examState !== "IN_PROGRESS") return;
    retryFailedSaves();
    try {
      const status = await apiFetch("/api/exam/status");
      if (status.status !== "IN_PROGRESS") showSubmittedView();
    } catch (_) {}
  }

  function retryFailedSaves() {
    if (state.examState !== "IN_PROGRESS" || !state.failedSaves.size) return;
    [...state.failedSaves.keys()].forEach((questionId) => queueSave(questionId).catch(() => {}));
  }

  document.querySelectorAll(".tab-button").forEach((button) => {
    button.addEventListener("click", () => switchTab(button.dataset.role));
  });
  document.getElementById("login-form").addEventListener("submit", handleLogin);
  document.getElementById("logout-btn").addEventListener("click", handleLogout);
  document.getElementById("start-button").addEventListener("click", startExam);
  document.getElementById("flag-btn").addEventListener("click", toggleFlag);
  document.getElementById("btn-prev").addEventListener("click", () => navigateTo(state.currentIndex - 1));
  document.getElementById("btn-next").addEventListener("click", () => navigateTo(state.currentIndex + 1));
  document.getElementById("open-submit-button").addEventListener("click", openSubmitDialog);
  document.getElementById("close-submit-button").addEventListener("click", () => document.getElementById("submit-modal").close());
  document.getElementById("confirm-submit-button").addEventListener("click", () => submitExam(false));
  // Theme toggle: inline head script applied the initial theme pre-paint;
  // this just flips it and persists the explicit choice.
  const themeToggle = document.getElementById("theme-toggle");
  function syncThemeToggle() {
    const dark = document.documentElement.dataset.theme === "dark";
    themeToggle.textContent = dark ? "Light" : "Dark";
    themeToggle.setAttribute("aria-pressed", String(dark));
    themeToggle.setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
  }
  themeToggle.addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    localStorage.setItem("exam-theme", next);
    syncThemeToggle();
  });
  syncThemeToggle();

  document.getElementById("refresh-violations").addEventListener("click", () => {
    loadLeaderboard();
    loadViolations();
  });
  document.getElementById("leaderboard-sort").addEventListener("change", renderLeaderboard);
  document.getElementById("create-user-form").addEventListener("submit", handleCreateUser);
  document.getElementById("add-user-row").addEventListener("click", addCreateUserRow);
  resetCreateUserRows();
  document.addEventListener("exam:visibility-return", reconcileStatus);
  window.addEventListener("online", retryFailedSaves);
  document.addEventListener("exam:server-submitted", () => showSubmittedView("violation"));
  restoreSession();
})();
