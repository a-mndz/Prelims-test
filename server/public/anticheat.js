// Client-side anti-cheat DETERRENTS + violation DETECTION beacons (plan §5, RULES #8).
//
// HONEST NAMING (RULES #8): nothing here PREVENTS cheating. Every handler below is
// bypassable via DevTools, disabling JS, or a second device — they raise friction and
// are in spec, that's all. The measures that actually raise the cost of cheating are
// server-side: per-participant shuffle (§3.1), single active session (§2.2), and
// server-enforced timing (§4.1). Do not let this file's presence create false confidence.
//
// The lines here that feed real server-side signals are the event beacons: they POST
// tab_blur / copy_paste / fullscreen_exit to /api/exam/event, which the server logs and
// thresholds (§5). The server decides consequences; the client only reports.
(function () {
  "use strict";

  const examIsActive = () => !document.getElementById("view-exam")?.classList.contains("hidden");

  // --- beacon (the real signal — server logs + thresholds it, §5) ---------------
  // sendBeacon cannot set the CSRF header (§2.1), so keepalive fetch carries
  // X-Requested-With and survives the tab being backgrounded.
  function reportEvent(type) {
    try {
      fetch("/api/exam/event", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Requested-With": "1" },
        body: JSON.stringify({ type }),
        keepalive: true, // survive the tab going to the background
        credentials: "same-origin",
      })
        .then((response) => response.json().catch(() => ({})))
        .then((result) => {
          if (result.consequence === "auto_submit") document.dispatchEvent(new Event("exam:server-submitted"));
        })
        .catch(() => {}); // detection is best-effort; the server sweep/threshold is the backstop
    } catch (_) {
      /* never let a beacon failure break the exam UI */
    }
  }

  // --- clipboard: blocked AND reported (deterrent + signal) ---------------------
  // preventDefault is the deterrent (a determined user disables JS); the copy_paste
  // beacon is the signal the server thresholds. contextmenu is swallow-only — a
  // right-click is not clipboard use.
  for (const evt of ["copy", "cut", "paste"]) {
    document.addEventListener(evt, (e) => {
      if (!examIsActive()) return;
      e.preventDefault();
      reportEvent("copy_paste");
    });
  }
  document.addEventListener("contextmenu", (e) => {
    if (examIsActive()) e.preventDefault();
  });

  // Best-effort block of common DevTools shortcuts. F12 and Ctrl+Shift+I/J/C.
  // Deterrent only — the browser menu still opens DevTools, and this is trivially
  // bypassed. Included because it raises friction and is in spec, not because it works.
  document.addEventListener("keydown", (e) => {
    const k = e.key.toUpperCase();
    if (examIsActive() && (e.key === "F12" || (e.ctrlKey && e.shiftKey && (k === "I" || k === "J" || k === "C")))) {
      e.preventDefault();
    }
  });

  // --- visibility: fires on tab switch, window blur, minimize -------------------
  function reportBlur() {
    if (!examIsActive() || document.visibilityState !== "hidden") return;
    reportEvent("tab_blur");
  }
  document.addEventListener("visibilitychange", reportBlur);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") document.dispatchEvent(new Event("exam:visibility-return"));
  });

  // --- fullscreen: leaving it mid-exam is a violation (app.js requests it on
  // login/start — requestFullscreen needs a user gesture, so it lives there).
  // Minimizing while fullscreen can fire BOTH this and tab_blur; both count.
  document.addEventListener("fullscreenchange", () => {
    if (examIsActive() && !document.fullscreenElement) reportEvent("fullscreen_exit");
  });
})();
