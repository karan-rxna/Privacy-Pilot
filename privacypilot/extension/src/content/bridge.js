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

  function flush() {
    flushTimer = null;
    if (!queue.length) return;
    const batch = queue.splice(0, queue.length);
    try {
      chrome.runtime.sendMessage({ type: "PP_EVENTS", events: batch }, () => {
        void chrome.runtime.lastError; // service worker asleep is fine
      });
    } catch {}
  }

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.source !== CHANNEL) return;
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

  // Report the policy link so the popup can offer analysis without a page scrape.
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
    const url = findPolicyLink();
    if (!url) return;
    try {
      chrome.runtime.sendMessage({ type: "PP_POLICY_LINK", url }, () => {
        void chrome.runtime.lastError;
      });
    } catch {}
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", reportPolicyLink, { once: true });
  } else {
    reportPolicyLink();
  }

  // Phishing signals need the DOM. Sample twice: once when the document is
  // ready, and again a moment later, because login forms are frequently
  // rendered by JavaScript after first paint.
  function scheduleDomSignals() {
    reportDomSignals();
    setTimeout(reportDomSignals, 1500);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", scheduleDomSignals, { once: true });
  } else {
    scheduleDomSignals();
  }

  /**
   * Facts the phishing module needs but cannot get from a URL alone.
   * Collected here, judged in the service worker, so the logic stays in one
   * testable module.
   */
  function collectDomSignals() {
    const passwords = document.querySelectorAll('input[type="password"]');
    const emails = document.querySelectorAll(
      'input[type="email"], input[name*="email" i], input[name*="user" i]'
    );

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
    // would match any incidental mention.
    const brandBits = [];
    for (const el of document.querySelectorAll(
      'h1, h2, [class*="logo" i], [class*="brand" i], img[alt], [aria-label]'
    )) {
      const text = el.getAttribute("alt") || el.getAttribute("aria-label") || el.textContent || "";
      const trimmed = text.trim().slice(0, 60);
      if (trimmed) brandBits.push(trimmed);
      if (brandBits.length >= 12) break;
    }

    return {
      passwordFields: passwords.length,
      emailFields: emails.length,
      title: (document.title || "").slice(0, 160),
      brandText: brandBits.join(" ").slice(0, 500),
      formActions: formActions.slice(0, 6)
    };
  }

  function reportDomSignals() {
    try {
      chrome.runtime.sendMessage(
        { type: "PP_DOM_SIGNALS", signals: collectDomSignals() },
        () => void chrome.runtime.lastError
      );
    } catch {}
  }

  chrome.runtime.onMessage.addListener((msg, _sender, respond) => {
    if (msg && msg.type === "PP_EXTRACT_POLICY") {
      const article = document.querySelector("main, article, [role='main']") || document.body;
      respond({ text: (article.innerText || "").slice(0, 60000), url: location.href });
      return true;
    }
    return false;
  });
})();
