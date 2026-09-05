// PrivacyPilot - ISOLATED world content script.
//
// Bridges the MAIN world hook (pageHook.js) to the service worker, and runs
// phishing detection once the DOM actually exists.

(() => {
  "use strict";

  const CHANNEL = "privacypilot";

  // The extension context dies on reload/update; sendMessage then throws.
  function send(message) {
    try {
      chrome.runtime.sendMessage(message, () => void chrome.runtime.lastError);
    } catch (_) {
      /* extension context invalidated - nothing useful to do */
    }
  }

  // ------------------------------------------------- page hook -> service worker
  window.addEventListener("message", (e) => {
    if (e.source !== window) return;
    const d = e.data;
    if (!d || d.channel !== CHANNEL || d.direction !== "to-extension") return;
    if (d.kind !== "event" || !d.event || typeof d.event.type !== "string") return;

    // The page shares this window, so it can forge these messages. We only
    // ever trust `type`, and we stamp the site ourselves rather than believing
    // whatever the message claims.
    send({
      type: "event",
      event: {
        type: String(d.event.type).slice(0, 32),
        site: location.hostname,
        url: location.origin,
        detail: d.event.detail || null,
        timestamp: Date.now()
      }
    });
  });

  // ------------------------------------------------- settings -> page hook
  function pushSettings(settings) {
    window.postMessage(
      { channel: CHANNEL, direction: "to-page", kind: "settings", settings },
      location.origin === "null" ? "*" : location.origin
    );
  }

  try {
    chrome.storage.local.get(["settings"], (data) => {
      if (chrome.runtime.lastError) return;
      const s = (data && data.settings) || {};
      pushSettings({
        blurLocation: !!s.blurLocation,
        blurRadiusMeters: s.blurRadiusMeters || 1000
      });
    });

    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== "local" || !changes.settings) return;
      const s = changes.settings.newValue || {};
      pushSettings({
        blurLocation: !!s.blurLocation,
        blurRadiusMeters: s.blurRadiusMeters || 1000
      });
    });
  } catch (_) {
    /* ignore */
  }

  // ------------------------------------------------------------ phishing checks
  // The original build ran this at document_start and never called it, so the
  // password-field check always saw an empty DOM.
  function runPhishingScan() {
    if (typeof analyzePhishing !== "function") return;
    let findings = null;
    try {
      findings = analyzePhishing();
    } catch (_) {
      return;
    }
    if (findings && findings.length) {
      send({ type: "phishing", site: location.hostname, findings });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", runPhishingScan, { once: true });
  } else {
    runPhishingScan();
  }
  // Login forms are often rendered by JS after DOMContentLoaded.
  setTimeout(runPhishingScan, 2500);
})();
