/**
 * PrivacyPilot AI — isolated world bridge.
 *
 * The MAIN world shim can see page APIs but not chrome.*. This script can see
 * chrome.* but not page APIs. It relays between the two, and is the only place
 * page-supplied data is validated before it reaches the extension.
 */
(() => {
  "use strict";

  const CHANNEL = "__privacypilot__";
  const VALID_KINDS = new Set(["permission", "fingerprint", "probe"]);
  const queue = [];
  let flushTimer = null;

  /** False once the extension has been reloaded out from under this page. */
  function alive() {
    return Boolean(chrome.runtime && chrome.runtime.id);
  }

  function toPage(payload) {
    try {
      window.postMessage(payload, location.origin === "null" ? "*" : location.origin);
    } catch {}
  }

  /* ---------- Event batching ---------- */

  function flush() {
    flushTimer = null;
    if (!queue.length || !alive()) return;
    const batch = queue.splice(0, queue.length);
    try {
      chrome.runtime.sendMessage({ type: "PP_EVENTS", events: batch }, () => {
        void chrome.runtime.lastError; // service worker asleep is fine
      });
    } catch {}
  }

  /* ---------- Messages from the shim ---------- */

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.source !== CHANNEL) return;

    // A deferred permission request. The page is blocked on a promise waiting
    // for this answer, so it goes straight through rather than being batched.
    if (data.kind === "ask") {
      if (!alive()) {
        toPage({ source: CHANNEL + ":decision", id: data.id, verdict: "allow" });
        return;
      }
      try {
        chrome.runtime.sendMessage({
          type: "PP_ASK_PERMISSION",
          id: data.id,
          api: String(data.api || "").slice(0, 64),
          detail: String(data.detail || "").slice(0, 64),
          script: String(data.script || "").slice(0, 300),
          origin: location.origin
        }, (response) => {
          void chrome.runtime.lastError;
          toPage({
            source: CHANNEL + ":decision",
            id: data.id,
            // Fail open on any error. A missing answer must not hang the page.
            verdict: (response && response.verdict) || "allow"
          });
        });
      } catch {
        toPage({ source: CHANNEL + ":decision", id: data.id, verdict: "allow" });
      }
      return;
    }

    if (!VALID_KINDS.has(data.kind)) return;

    queue.push({
      kind: data.kind,
      api: String(data.api || "").slice(0, 64),
      detail: data.detail ? String(data.detail).slice(0, 120) : null,
      frame: data.frame === "iframe" ? "iframe" : "top",
      script: String(data.script || "").slice(0, 300),
      at: Number(data.at) || Date.now()
    });

    if (queue.length > 40) queue.splice(0, queue.length - 40);
    if (!flushTimer) flushTimer = setTimeout(flush, 250);
  });

  /* ---------- Fuzzing config ---------- */

  /**
   * Sent immediately, not on DOMContentLoaded: the shim needs its seed before
   * the page runs any fingerprinting, and plenty of sites fingerprint during
   * initial parse.
   */
  function sendFuzzConfig() {
    if (!alive()) return;
    try {
      chrome.runtime.sendMessage({ type: "PP_GET_FUZZ" }, (res) => {
        if (chrome.runtime.lastError || !res) return;
        toPage({
          source: CHANNEL + ":config",
          seed: res.seed,
          mode: res.mode,
          locationLevel: res.locationLevel
        });
      });
    } catch {}
  }

  sendFuzzConfig();

  /* ---------- Privacy policy link ---------- */

  function findPolicyLink() {
    const patterns = /privacy|datenschutz|confidentialit|privacidad|gizlilik/i;
    for (const a of document.querySelectorAll("a[href]")) {
      const text = (a.textContent || "") + " " + (a.getAttribute("aria-label") || "");
      if (patterns.test(text) || patterns.test(a.getAttribute("href") || "")) {
        try {
          return new URL(a.getAttribute("href"), location.href).href;
        } catch {}
      }
    }
    return null;
  }

  function reportPolicyLink() {
    if (!alive()) return;
    const url = findPolicyLink();
    if (!url) return;
    try {
      chrome.runtime.sendMessage({ type: "PP_POLICY_LINK", url }, () => {
        void chrome.runtime.lastError;
      });
    } catch {}
  }

  /* ---------- Phishing signals ---------- */

  /**
   * Facts the phishing module needs but cannot get from a URL alone.
   * Collected here, judged in the service worker, so the detection logic stays
   * in one testable module.
   */
  function collectDomSignals() {
    // Only forms that actually take a password. A newsletter signup posting
    // off-origin is not a credential-harvesting signal.
    const formActions = [];
    for (const form of document.querySelectorAll("form")) {
      if (!form.querySelector('input[type="password"]')) continue;
      const action = form.getAttribute("action");
      if (!action) continue;
      try {
        formActions.push(new URL(action, location.href).href);
      } catch {}
    }

    // Text most likely to carry a brand claim: headings, logo alt text, and
    // anything with a brand-ish class. Deliberately not the whole page, which
    // would match any incidental mention of a company name.
    const brandBits = [];
    for (const el of document.querySelectorAll(
      'h1, h2, [class*="logo" i], [class*="brand" i], img[alt], [aria-label]'
    )) {
      const text =
        el.getAttribute("alt") || el.getAttribute("aria-label") || el.textContent || "";
      const trimmed = text.trim().slice(0, 60);
      if (trimmed) brandBits.push(trimmed);
      if (brandBits.length >= 12) break;
    }

    return {
      passwordFields: document.querySelectorAll('input[type="password"]').length,
      emailFields: document.querySelectorAll(
        'input[type="email"], input[name*="email" i], input[name*="user" i]'
      ).length,
      title: (document.title || "").slice(0, 160),
      brandText: brandBits.join(" ").slice(0, 500),
      formActions: formActions.slice(0, 6)
    };
  }

  let lastSignature = "";

  function reportDomSignals() {
    if (!alive()) return;
    const signals = collectDomSignals();

    // The second sample usually finds the same DOM as the first. Skip the
    // resend when nothing changed, so the worker does not re-run detection and
    // redraw the badge for no reason.
    const signature =
      `${signals.passwordFields}|${signals.formActions.join(",")}|${signals.title}`;
    if (signature === lastSignature) return;
    lastSignature = signature;

    try {
      chrome.runtime.sendMessage(
        { type: "PP_DOM_SIGNALS", signals },
        () => void chrome.runtime.lastError
      );
    } catch {}
  }

  /* ---------- Startup ---------- */

  function onReady() {
    reportPolicyLink();
    reportDomSignals();
    // Sample again shortly after: login forms are frequently rendered by
    // JavaScript after first paint, so one sample misses most of them.
    setTimeout(reportDomSignals, 1500);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", onReady, { once: true });
  } else {
    onReady();
  }

  /* ---------- Requests from the extension ---------- */

  chrome.runtime.onMessage.addListener((msg, _sender, respond) => {
    if (msg && msg.type === "PP_EXTRACT_POLICY") {
      const article =
        document.querySelector("main, article, [role='main']") || document.body;
      respond({ text: (article.innerText || "").slice(0, 60000), url: location.href });
      return true;
    }
    return false;
  });
})();
