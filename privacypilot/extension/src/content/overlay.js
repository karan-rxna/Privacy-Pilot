/**
 * PrivacyPilot AI — in-page overlay.
 *
 * Renders a warning card over the page when a site does something worth
 * interrupting for. Three constraints shaped the implementation:
 *
 *  1. It must not break the page. Everything lives in a closed shadow root, so
 *     no page CSS can reach in and no extension CSS leaks out.
 *  2. It must not block the page. The host element is pointer-events: none;
 *     only the card itself accepts clicks. Everything around it stays usable.
 *  3. It must not nag. It fades to near-transparent after a few seconds,
 *     collapses to a small pill, and never reappears once dismissed for a host.
 */

if (window.top === window && location.protocol.startsWith("http")) {
  (() => {
    "use strict";

    const HOST_ID = "privacypilot-overlay-host";
    if (document.getElementById(HOST_ID)) return;

    const SEVERITY_COLOR = {
      critical: "#FB7185",
      high: "#FBBF24",
      moderate: "#4FE3F5"
    };

    let shadow = null;
    let host = null;
    let alert = null;
    let phishing = null;
    let collapsed = false;
    let dismissed = false;
    let fadeTimer = null;
    let pollTimer = null;

    /* ------------------------------------------------------------------ */

    const CSS = `
      :host { all: initial; }
      * { box-sizing: border-box; margin: 0; padding: 0;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; }

      .wrap {
        position: fixed; right: 20px; bottom: 20px; width: 344px; max-width: calc(100vw - 40px);
        pointer-events: auto; z-index: 2147483647;
        opacity: 0; transform: translateY(10px);
        transition: opacity 260ms ease, transform 260ms cubic-bezier(0.2, 0.8, 0.2, 1);
      }
      .wrap.in { opacity: 1; transform: translateY(0); }
      .wrap.faded { opacity: 0.34; }
      .wrap:hover { opacity: 1; }

      .card {
        background: rgba(9, 15, 28, 0.82);
        backdrop-filter: blur(22px) saturate(150%);
        -webkit-backdrop-filter: blur(22px) saturate(150%);
        border: 1px solid rgba(96, 205, 255, 0.22);
        border-radius: 14px;
        color: #E8F1FF;
        overflow: hidden;
      }

      .top {
        display: flex; align-items: center; gap: 9px;
        padding: 11px 13px; border-bottom: 1px solid rgba(96, 205, 255, 0.12);
      }
      .score {
        font-family: ui-monospace, "SF Mono", Menlo, monospace;
        font-size: 15px; font-weight: 500; line-height: 1;
        padding: 5px 8px; border-radius: 7px;
        border: 1px solid currentColor;
      }
      .top h1 { font-size: 12.5px; font-weight: 500; flex: 1; letter-spacing: -0.01em; }
      .top .hint {
        font-family: ui-monospace, Menlo, monospace; font-size: 9.5px;
        color: #5C6F8C; letter-spacing: 0.06em; white-space: nowrap;
      }
      .x {
        background: none; border: none; color: #5C6F8C; cursor: pointer;
        font-size: 17px; line-height: 1; padding: 0 2px;
      }
      .x:hover { color: #E8F1FF; }
      .x:focus-visible { outline: 2px solid #4FE3F5; outline-offset: 2px; border-radius: 3px; }

      .body { padding: 4px 13px 12px; max-height: 46vh; overflow-y: auto; }
      .body::-webkit-scrollbar { width: 6px; }
      .body::-webkit-scrollbar-thumb { background: rgba(96,205,255,0.2); border-radius: 3px; }

      .finding { padding: 11px 0; border-bottom: 1px solid rgba(96, 205, 255, 0.09); }
      .finding:last-child { border-bottom: none; }
      .fh { display: flex; align-items: flex-start; gap: 8px; margin-bottom: 5px; }
      .dot { width: 6px; height: 6px; border-radius: 50%; margin-top: 5px; flex: 0 0 6px; }
      .fh h2 { font-size: 12.5px; font-weight: 500; line-height: 1.4; }
      .harm { font-size: 11.5px; line-height: 1.55; color: #A9BDD8; padding-left: 14px; }
      .who { font-size: 10.5px; line-height: 1.5; color: #5C6F8C; padding-left: 14px; margin-top: 4px;
             font-family: ui-monospace, Menlo, monospace; word-break: break-word; }

      .acts { display: flex; gap: 7px; padding: 10px 13px;
              border-top: 1px solid rgba(96, 205, 255, 0.12); }
      button.act {
        flex: 1; font-size: 11.5px; padding: 7px 10px; cursor: pointer;
        color: #E8F1FF; background: rgba(76, 141, 255, 0.16);
        border: 1px solid rgba(96, 205, 255, 0.28); border-radius: 8px;
        transition: background 130ms ease, border-color 130ms ease;
      }
      button.act:hover { background: rgba(79, 227, 245, 0.24); border-color: #4FE3F5; }
      button.act:focus-visible { outline: 2px solid #4FE3F5; outline-offset: 2px; }
      button.act.ghost { background: transparent; color: #8AA0C2; }
      button.act[disabled] { opacity: 0.5; cursor: default; }

      .pill {
        display: flex; align-items: center; gap: 8px; cursor: pointer;
        padding: 8px 13px; border-radius: 999px;
        background: rgba(9, 15, 28, 0.82);
        backdrop-filter: blur(22px) saturate(150%);
        -webkit-backdrop-filter: blur(22px) saturate(150%);
        border: 1px solid rgba(96, 205, 255, 0.22);
        color: #E8F1FF; font-size: 11.5px; margin-left: auto; width: max-content;
      }
      .pill:hover { border-color: #4FE3F5; }
      .pill .n { font-family: ui-monospace, Menlo, monospace; font-weight: 500; }

      .done { padding: 14px 13px; font-size: 11.5px; color: #34D399; line-height: 1.5; }

      /* Phishing warning. Deliberately not the same visual language as the
         privacy card: wider, warmer, anchored top-centre, no auto-fade. */
      .wrap.phish { right: 50%; transform: translate(50%, -10px); bottom: auto; top: 18px; width: 420px; }
      .wrap.phish.in { transform: translate(50%, 0); }
      .wrap.phish.faded { opacity: 1; }
      .card.phish { border-color: rgba(251, 113, 133, 0.5); background: rgba(28, 10, 16, 0.9); }
      .card.phish .top { border-bottom-color: rgba(251, 113, 133, 0.24); }
      .warnmark {
        width: 22px; height: 22px; border-radius: 50%; flex: 0 0 22px;
        display: grid; place-items: center; font-size: 13px; font-weight: 700;
        background: rgba(251, 113, 133, 0.18); color: #FB7185;
      }
      .card.phish .top h1 { color: #FFE4E6; font-weight: 600; }
      .addr {
        font-family: ui-monospace, Menlo, monospace; font-size: 11.5px;
        padding: 8px 13px; color: #FDA4AF; background: rgba(251, 113, 133, 0.08);
        border-bottom: 1px solid rgba(251, 113, 133, 0.16);
        word-break: break-all;
      }
      .advice {
        font-size: 11.5px; line-height: 1.55; color: #FECDD3;
        padding-left: 14px; margin-top: 6px; font-weight: 500;
      }
      .caveat {
        padding: 9px 13px; font-size: 10.5px; line-height: 1.5; color: #8AA0C2;
        border-top: 1px solid rgba(251, 113, 133, 0.16);
      }

      @media (prefers-reduced-motion: reduce) {
        .wrap { transition: none; }
      }
    `;

    /* ------------------------------------------------------------------ */

    function mount() {
      host = document.createElement("div");
      host.id = HOST_ID;
      host.style.cssText =
        "all:initial;position:fixed;inset:0;pointer-events:none;z-index:2147483647";
      shadow = host.attachShadow({ mode: "closed" });
      const style = document.createElement("style");
      style.textContent = CSS;
      shadow.append(style, document.createElement("div"));
      (document.body || document.documentElement).appendChild(host);
    }

    function scoreColor(n) {
      if (n >= 80) return "#34D399";
      if (n >= 60) return "#FBBF24";
      return "#FB7185";
    }

    function render() {
      if (!shadow) return;
      const root = shadow.lastElementChild;

      if (dismissed) {
        root.innerHTML = "";
        return;
      }

      // A suspected credential-harvesting page outranks everything else. If both
      // are present, the phishing warning is what the user sees.
      if (phishing) {
        renderPhishing(root);
        return;
      }

      if (!alert) {
        root.innerHTML = "";
        return;
      }

      if (collapsed) {
        root.innerHTML = `
          <div class="wrap in">
            <div class="pill" part="pill" role="button" tabindex="0">
              <span class="n" style="color:${scoreColor(alert.score)}">${alert.score}</span>
              <span>${alert.findings.length} privacy issue${alert.findings.length > 1 ? "s" : ""}</span>
            </div>
          </div>`;
        const pill = root.querySelector(".pill");
        pill.addEventListener("click", () => { collapsed = false; render(); });
        pill.addEventListener("keydown", (e) => {
          if (e.key === "Enter" || e.key === " ") { e.preventDefault(); collapsed = false; render(); }
        });
        return;
      }

      const permissionFinding = alert.findings.find((f) => f.kind === "permission");
      const canBlock = alert.blockableHosts.length > 0;

      root.innerHTML = `
        <div class="wrap" role="dialog" aria-label="Privacy warning for this page">
          <div class="card">
            <div class="top">
              <span class="score" style="color:${scoreColor(alert.score)}">${alert.score}</span>
              <h1>What this page is doing</h1>
              <span class="hint">Alt+Shift+P</span>
              <button class="x" aria-label="Collapse">&minus;</button>
            </div>
            <div class="body">
              ${alert.findings.map((f) => `
                <div class="finding">
                  <div class="fh">
                    <span class="dot" style="background:${SEVERITY_COLOR[f.severity]}"></span>
                    <h2>${f.headline}</h2>
                  </div>
                  <p class="harm">${f.harm}</p>
                  <p class="who">${f.who}</p>
                </div>`).join("")}
            </div>
            <div class="acts">
              ${canBlock ? `<button class="act" data-a="block">Block ${alert.blockableHosts.length} tracker${alert.blockableHosts.length > 1 ? "s" : ""}</button>` : ""}
              ${permissionFinding ? `<button class="act" data-a="deny">Deny ${permissionFinding.detail}</button>` : ""}
              <button class="act ghost" data-a="dismiss">Not now</button>
            </div>
          </div>
        </div>`;

      requestAnimationFrame(() => root.querySelector(".wrap")?.classList.add("in"));

      root.querySelector(".x").addEventListener("click", () => { collapsed = true; render(); });
      root.querySelectorAll("[data-a]").forEach((btn) =>
        btn.addEventListener("click", () => act(btn.dataset.a, btn, permissionFinding))
      );

      const wrap = root.querySelector(".wrap");
      wrap.addEventListener("mouseenter", () => {
        wrap.classList.remove("faded");
        clearTimeout(fadeTimer);
      });
      wrap.addEventListener("mouseleave", scheduleFade);
      scheduleFade();
    }

    /**
     * The phishing warning.
     *
     * Differences from the privacy card, all deliberate:
     *  - It does not auto-fade. A warning that dims itself while someone is
     *    typing a password is worse than no warning.
     *  - It is anchored top-centre, near the address bar the user needs to read.
     *  - The dismiss button says "I know this site", not "Close", so dismissing
     *    is an assertion rather than a reflex.
     *  - It carries a caveat stating that no warning does not mean safe. This is
     *    the only honest way to ship heuristic phishing detection.
     */
    function renderPhishing(root) {
      const collapse = collapsed;
      if (collapse) {
        root.innerHTML = `
          <div class="wrap in">
            <div class="pill" role="button" tabindex="0" style="border-color:rgba(251,113,133,0.5)">
              <span class="n" style="color:#FB7185">!</span>
              <span>Address looks suspicious</span>
            </div>
          </div>`;
        const pill = root.querySelector(".pill");
        pill.addEventListener("click", () => { collapsed = false; render(); });
        pill.addEventListener("keydown", (e) => {
          if (e.key === "Enter" || e.key === " ") { e.preventDefault(); collapsed = false; render(); }
        });
        return;
      }

      root.innerHTML = `
        <div class="wrap phish" role="alertdialog" aria-label="Suspicious address warning">
          <div class="card phish">
            <div class="top">
              <span class="warnmark">!</span>
              <h1>Check this address before you type anything</h1>
              <span class="hint">Alt+Shift+P</span>
            </div>
            <div class="addr">${phishing.hostname}</div>
            <div class="body">
              ${phishing.findings.map((f) => `
                <div class="finding">
                  <div class="fh">
                    <span class="dot" style="background:${
                      f.confidence === "high" ? "#FB7185" : f.confidence === "medium" ? "#FBBF24" : "#8AA0C2"
                    }"></span>
                    <h2>${f.headline}</h2>
                  </div>
                  <p class="harm">${f.detail}</p>
                  ${f.advice ? `<p class="advice">${f.advice}</p>` : ""}
                </div>`).join("")}
            </div>
            <p class="caveat">
              This is a warning, not a verdict. PrivacyPilot checks how an address is
              written &mdash; it cannot tell you a site is safe, and the absence of a
              warning never means a site is trustworthy.
            </p>
            <div class="acts">
              <button class="act" data-p="collapse">Keep this visible</button>
              <button class="act ghost" data-p="known">I know this site</button>
            </div>
          </div>
        </div>`;

      requestAnimationFrame(() => root.querySelector(".wrap")?.classList.add("in"));

      root.querySelector('[data-p="collapse"]').addEventListener("click", () => {
        collapsed = true;
        render();
      });
      root.querySelector('[data-p="known"]').addEventListener("click", () => {
        dismissed = true;
        render();
      });
      // Note the absence of scheduleFade() here. Intentional.
    }

    function scheduleFade() {
      clearTimeout(fadeTimer);
      fadeTimer = setTimeout(() => {
        shadow?.lastElementChild?.querySelector(".wrap")?.classList.add("faded");
      }, 5000);
    }

    async function act(action, button, permissionFinding) {
      if (action === "dismiss") {
        dismissed = true;
        render();
        return;
      }

      button.disabled = true;
      button.textContent = "Working…";

      try {
        if (action === "block") {
          const res = await chrome.runtime.sendMessage({
            type: "PP_BLOCK",
            hosts: alert.blockableHosts
          });
          showDone(`Blocked ${res.blocked} tracker host${res.blocked > 1 ? "s" : ""}. Reload the page to see the difference.`);
        } else if (action === "deny") {
          const res = await chrome.runtime.sendMessage({
            type: "PP_DENY_PERMISSION",
            origin: location.origin,
            detail: permissionFinding.detail
          });
          showDone(res.ok
            ? `${permissionFinding.detail} is now blocked for ${location.hostname}.`
            : res.reason);
        }
      } catch (error) {
        button.disabled = false;
        button.textContent = "Try again";
      }
    }

    function showDone(message) {
      const card = shadow.lastElementChild.querySelector(".card");
      if (!card) return;
      card.innerHTML = `<p class="done">${message}</p>`;
      setTimeout(() => { collapsed = true; render(); }, 3200);
    }

    /* ------------------------------------------------------------------ */

    function poll() {
      chrome.runtime.sendMessage({ type: "PP_GET_ALERT" }, (response) => {
        if (chrome.runtime.lastError || !response) return;

        const phishChanged = JSON.stringify(response.phishing) !== JSON.stringify(phishing);
        const alertChanged = JSON.stringify(response.alert) !== JSON.stringify(alert);

        phishing = response.phishing || null;
        alert = response.alert || null;

        if ((phishChanged || alertChanged) && !dismissed) {
          // A newly detected phishing signal re-opens the panel even if the user
          // had collapsed a privacy card, because it is a different message.
          if (phishChanged && phishing) collapsed = false;
          render();
        }
      });
    }

    chrome.runtime.onMessage.addListener((msg) => {
      if (msg?.type !== "PP_TOGGLE_OVERLAY") return;
      if (dismissed) {
        dismissed = false;
        collapsed = false;
      } else {
        collapsed = !collapsed;
      }
      render();
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && alert && !collapsed && !dismissed) {
        collapsed = true;
        render();
      }
    }, true);

    mount();
    pollTimer = setInterval(poll, 1800);
    setTimeout(poll, 900);
  })();
}
