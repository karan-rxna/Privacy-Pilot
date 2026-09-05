/**
 * PrivacyPilot AI — service worker.
 *
 * Owns all state. Content scripts only report; the popup and dashboard only read.
 * MV3 service workers are killed aggressively, so nothing lives in memory that
 * we cannot rebuild from chrome.storage.
 */

import { identify, isThirdParty } from "../lib/trackers.js";
import { computeScore } from "../lib/score.js";
import { buildAlert } from "../lib/harms.js";
import { blockHosts, denyPermission, listBlocked } from "../lib/blocking.js";
import { analyzePhishing } from "../lib/phishing.js";
import { explainRequest, SCOPES } from "../lib/consent.js";
import {
  seedFor, MODES, LOCATION_GRIDS, DEFAULT_MODE, DEFAULT_LOCATION_LEVEL
} from "../lib/fuzzing.js";

const BACKEND = "http://127.0.0.1:8000";
const tabs = new Map(); // tabId -> live observation record

// Pending consent requests: `${tabId}:${requestId}` -> sendResponse.
// The page is blocked on a promise until one of these is called.
const askQueue = new Map();

// Grants that expire: `${origin}:${detail}` -> "once" | "session".
// There is deliberately no permanent scope.
const sessionGrants = new Map();

function blank(hostname = "") {
  return {
    hostname,
    startedAt: Date.now(),
    events: [],
    trackers: [],
    trackerHosts: new Set(),
    thirdPartyCookies: 0,
    policyUrl: null,
    policyFindings: null,
    policySummary: null,
    domSignals: null,
    phishing: null,
    url: null
  };
}

function getState(tabId, hostname) {
  let state = tabs.get(tabId);
  if (!state || (hostname && state.hostname !== hostname)) {
    state = blank(hostname || (state && state.hostname) || "");
    tabs.set(tabId, state);
  }
  return state;
}

function serialize(state) {
  const { trackerHosts, ...rest } = state;
  return rest;
}

/* ---------- Fuzzing settings ---------- */

function originOf(url) {
  try { return new URL(url).origin; } catch { return ""; }
}

/** The per-site fuzzing setting, with the defaults applied. */
async function fuzzSettingFor(origin) {
  const { fuzzModes = {} } = await chrome.storage.local.get("fuzzModes");
  const setting = fuzzModes[origin] || {};
  return {
    mode: MODES[setting.mode] ? setting.mode : DEFAULT_MODE,
    level: LOCATION_GRIDS[setting.level] !== undefined
      ? setting.level
      : DEFAULT_LOCATION_LEVEL
  };
}

/**
 * The per-install salt, created on demand.
 *
 * onInstalled alone is not enough: it does not fire for an unpacked extension
 * already loaded, and a failed write leaves it missing forever. Without a salt
 * every install distorts a given site identically, which is itself a
 * fingerprint — the one thing the salt exists to prevent — so it is worth
 * checking on the path that actually needs it.
 */
async function ensureSalt() {
  const stored = await chrome.storage.local.get("fuzzSalt");
  if (stored.fuzzSalt) return stored.fuzzSalt;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const salt = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  await chrome.storage.local.set({ fuzzSalt: salt });
  return salt;
}

/* ---------- Tracker observation ---------- */

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) return;
    try {
      const url = new URL(details.url);
      const requestHost = url.hostname;
      const state = tabs.get(details.tabId);
      if (!state) return;

      const hit = identify(requestHost, url.pathname);
      if (!hit || hit.category === "cdn") return;
      if (!isThirdParty(requestHost, state.hostname)) return;
      if (state.trackerHosts.has(requestHost)) return;

      state.trackerHosts.add(requestHost);
      state.trackers.push({ ...hit, host: requestHost, at: Date.now() });
      updateBadge(details.tabId, state);
    } catch {}
  },
  { urls: ["<all_urls>"] }
);

/* ---------- Navigation lifecycle ---------- */

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "loading" && tab.url) {
    try {
      const host = new URL(tab.url).hostname;
      const existing = tabs.get(tabId);
      if (!existing || existing.hostname !== host) {
        // Navigating away inside a tab should revoke too, not just closing it.
        if (existing && existing.hostname) {
          revokeIfGone(`https://${existing.hostname}`).catch(() => {});
        }
        tabs.set(tabId, blank(host));
      }
    } catch {}
  }
  if (info.status === "complete") {
    const state = tabs.get(tabId);
    if (state) {
      countThirdPartyCookies(tabId, state);
      persist(state);
    }
  }
});

/**
 * Revoke scoped grants once the user has left a site entirely.
 *
 * Revokes to 'ask', never 'block'. 'block' means the site can never request
 * again, which surprises users badly and looks like the extension broke it.
 */
async function revokeIfGone(origin) {
  if (!origin) return;
  const open = await chrome.tabs.query({});
  const stillOpen = open.some((t) => {
    try { return t.url && new URL(t.url).origin === origin; } catch { return false; }
  });
  if (stillOpen) return;

  const SETTING_FOR = { microphone: "microphone", camera: "camera", location: "location" };

  for (const key of [...sessionGrants.keys()]) {
    if (!key.startsWith(origin + ":")) continue;
    sessionGrants.delete(key);
    const detail = key.slice(origin.length + 1);
    const setting = SETTING_FOR[detail.split(" ")[0]];
    if (setting && chrome.contentSettings[setting]) {
      chrome.contentSettings[setting]
        .set({ primaryPattern: `${origin}/*`, setting: "ask" })
        .catch(() => {});
    }
  }
}

chrome.tabs.onRemoved.addListener(async (tabId) => {
  const state = tabs.get(tabId);
  tabs.delete(tabId);
  // Drop any consent request this tab was waiting on.
  for (const key of [...askQueue.keys()]) {
    if (key.startsWith(tabId + ":")) askQueue.delete(key);
  }
  if (state && state.hostname) await revokeIfGone(`https://${state.hostname}`);
});

async function countThirdPartyCookies(tabId, state) {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab.url || !tab.url.startsWith("http")) return;
    const all = await chrome.cookies.getAll({});
    const base = (h) => h.replace(/^\./, "").split(".").slice(-2).join(".");
    const pageBase = base(state.hostname);
    state.thirdPartyCookies = all.filter((c) => base(c.domain) !== pageBase).length;
    updateBadge(tabId, state);
  } catch {}
}

/* ---------- Badge ---------- */

function updateBadge(tabId, state) {
  // A suspected credential-harvesting page outranks the score. Showing "72"
  // next to a phishing warning would read as reassurance.
  if (state.phishing) {
    chrome.action.setBadgeText({ tabId, text: "!" }).catch(() => {});
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#EF4444" }).catch(() => {});
    return;
  }
  const { score } = computeScore(serialize(state));
  const color =
    score >= 80 ? "#22C55E" : score >= 60 ? "#EAB308" : score >= 40 ? "#F97316" : "#EF4444";
  chrome.action.setBadgeText({ tabId, text: String(score) }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(() => {});
}

/* ---------- Persistence ---------- */

async function persist(state) {
  if (!state.hostname) return;
  const result = computeScore(serialize(state));
  const key = `site:${state.hostname}`;
  const stored = await chrome.storage.local.get(key);
  const history = stored[key]?.history || [];
  history.push({ at: Date.now(), score: result.score });

  await chrome.storage.local.set({
    [key]: {
      hostname: state.hostname,
      lastSeen: Date.now(),
      score: result.score,
      band: result.band,
      trackers: state.trackers.map((t) => ({ name: t.name, category: t.category })),
      permissions: result.permissions.map((p) => ({ label: p.label, level: p.level })),
      history: history.slice(-30)
    }
  });
}

/* ---------- Messaging ---------- */

chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  if (!msg || !msg.type) return false;

  if (msg.type === "PP_EVENTS" && sender.tab) {
    const state = getState(
      sender.tab.id,
      sender.tab.url ? new URL(sender.tab.url).hostname : ""
    );
    state.events.push(...msg.events);
    if (state.events.length > 300) state.events.splice(0, state.events.length - 300);
    updateBadge(sender.tab.id, state);
    return false;
  }

  if (msg.type === "PP_POLICY_LINK" && sender.tab) {
    const state = tabs.get(sender.tab.id);
    if (state && !state.policyUrl) state.policyUrl = msg.url;
    return false;
  }

  if (msg.type === "PP_DOM_SIGNALS" && sender.tab) {
    const state = tabs.get(sender.tab.id);
    if (state) {
      state.domSignals = msg.signals;
      state.url = sender.tab.url;
      state.phishing = analyzePhishing(sender.tab.url || "", msg.signals);
      updateBadge(sender.tab.id, state);
    }
    return false;
  }

  if (msg.type === "PP_GET_TAB") {
    (async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab) return respond({ error: "no_tab" });
      const state = tabs.get(tab.id) || blank(tab.url ? new URL(tab.url).hostname : "");
      const plain = serialize(state);
      respond({
        tabId: tab.id,
        url: tab.url,
        origin: originOf(tab.url),
        state: plain,
        result: computeScore(plain),
        phishing: state.phishing || null,
        fuzz: await fuzzSettingFor(originOf(tab.url))
      });
    })();
    return true;
  }

  if (msg.type === "PP_GET_ALERT") {
    const tabId = sender.tab?.id;
    const state = tabId != null ? tabs.get(tabId) : null;
    (async () => {
      // The overlay needs the fuzzing mode to state it on the card, so this
      // reads storage and is now async.
      const fuzz = await fuzzSettingFor(originOf(sender.tab?.url));
      if (!state || !state.hostname) {
        respond({ alert: null, phishing: null, fuzz });
        return;
      }
      const plain = serialize(state);
      respond({
        alert: buildAlert(plain, computeScore(plain)),
        phishing: state.phishing || null,
        fuzz
      });
    })();
    return true;
  }

  if (msg.type === "PP_ANALYZE_POLICY") {
    (async () => {
      try {
        respond(await analyzePolicy(msg.tabId));
      } catch (error) {
        respond({ error: String(error.message || error) });
      }
    })();
    return true;
  }

  if (msg.type === "PP_ASK_PERMISSION" && sender.tab) {
    const tabId = sender.tab.id;
    const key = `${tabId}:${msg.id}`;
    const grantKey = `${msg.origin}:${msg.detail}`;

    // Already granted for this visit — do not ask twice.
    if (sessionGrants.has(grantKey)) {
      respond({ verdict: "allow" });
      return false;
    }

    askQueue.set(key, respond);
    const state = tabs.get(tabId);
    const explanation = explainRequest(
      state ? state.hostname : "", msg.detail, msg.script
    );

    chrome.tabs
      .sendMessage(tabId, { type: "PP_SHOW_CONSENT", requestId: msg.id, explanation })
      .catch(() => {
        // No overlay on this page (chrome://, PDFs). Fail open.
        askQueue.delete(key);
        respond({ verdict: "allow" });
      });
    return true; // keep the channel open until the user decides
  }

  if (msg.type === "PP_CONSENT_DECISION" && sender.tab) {
    const key = `${sender.tab.id}:${msg.requestId}`;
    const respondToPage = askQueue.get(key);
    if (!respondToPage) return false;
    askQueue.delete(key);

    const scope = SCOPES[msg.scope] || SCOPES.deny;
    if (scope.id === "deny") {
      denyPermission(msg.origin, msg.detail).catch(() => {});
      respondToPage({ verdict: "deny" });
    } else {
      sessionGrants.set(`${msg.origin}:${msg.detail}`, scope.id);
      respondToPage({ verdict: "allow" });
    }
    return false;
  }

  if (msg.type === "PP_GET_FUZZ" && sender.tab) {
    (async () => {
      const origin = originOf(sender.tab.url);
      const [salt, setting] = await Promise.all([
        ensureSalt(),
        fuzzSettingFor(origin)
      ]);
      respond({
        seed: seedFor(origin, salt),
        mode: setting.mode,
        locationLevel: setting.level
      });
    })();
    return true;
  }

  if (msg.type === "PP_SET_FUZZ_MODE") {
    (async () => {
      // Validate against MODES. An unrecognised mode would read as "not
      // approximate" everywhere in the shim and silently disable fuzzing for
      // the site — a privacy tool must never fail quietly open.
      if (!MODES[msg.mode] || !msg.origin) {
        respond({ ok: false, reason: "Unknown mode." });
        return;
      }
      const level = LOCATION_GRIDS[msg.level] !== undefined
        ? msg.level
        : DEFAULT_LOCATION_LEVEL;

      const { fuzzModes = {} } = await chrome.storage.local.get("fuzzModes");
      fuzzModes[msg.origin] = { mode: msg.mode, level };
      await chrome.storage.local.set({ fuzzModes });
      respond({ ok: true, mode: msg.mode, level });
    })();
    return true;
  }

  if (msg.type === "PP_BLOCK") {
    (async () => {
      try {
        const result = await blockHosts(msg.hosts || []);
        // Blocked hosts are no longer present on the page, so drop them from
        // the count. Otherwise the score never improves and blocking looks
        // like it did nothing.
        const tabId = sender.tab?.id;
        const state = tabId != null ? tabs.get(tabId) : null;
        if (state) {
          const blocked = new Set(msg.hosts || []);
          state.trackers = state.trackers.filter((t) => !blocked.has(t.host));
          blocked.forEach((h) => state.trackerHosts.delete(h));
          updateBadge(tabId, state);
        }
        respond(result);
      } catch (error) {
        respond({ blocked: 0, error: String(error.message || error) });
      }
    })();
    return true;
  }

  if (msg.type === "PP_DENY_PERMISSION") {
    (async () => {
      try {
        respond(await denyPermission(msg.origin, msg.detail));
      } catch (error) {
        respond({ ok: false, reason: String(error.message || error) });
      }
    })();
    return true;
  }

  if (msg.type === "PP_BLOCKED_LIST") {
    (async () => respond({ hosts: await listBlocked() }))();
    return true;
  }

  if (msg.type === "PP_ALL_SITES") {
    (async () => {
      const all = await chrome.storage.local.get(null);
      const sites = Object.entries(all)
        .filter(([k]) => k.startsWith("site:"))
        .map(([, v]) => v)
        .sort((a, b) => b.lastSeen - a.lastSeen);
      respond({ sites });
    })();
    return true;
  }

  return false;
});

/* ---------- Policy analysis ---------- */

async function analyzePolicy(tabId) {
  const state = tabs.get(tabId);
  if (!state) throw new Error("No observation record for this tab.");

  let text = "";
  let sourceUrl = state.policyUrl;

  if (sourceUrl) {
    const response = await fetch(sourceUrl, { credentials: "omit" });
    if (!response.ok) throw new Error(`Policy page returned ${response.status}.`);
    const html = await response.text();
    text = html
      .replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  } else {
    const extracted = await chrome.tabs.sendMessage(tabId, { type: "PP_EXTRACT_POLICY" });
    text = extracted?.text || "";
    sourceUrl = extracted?.url;
  }

  if (text.length < 400) throw new Error("Could not find enough policy text to analyse.");

  try {
    const health = await fetch(`${BACKEND}/health`, { method: "GET" });
    if (health.ok) {
      const info = await health.json();
      if (!info.key_configured) {
        throw new Error(
          "Backend is running but no API key is configured. Set OPENAI_API_KEY or GEMINI_API_KEY and restart it."
        );
      }
    }
  } catch (error) {
    if (error.message.includes("API key")) throw error;
    throw new Error(
      `Cannot reach the analysis service at ${BACKEND}. Start it with: uvicorn main:app --port 8000`
    );
  }

  let response;
  try {
    response = await fetch(`${BACKEND}/analyze-policy`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: text.slice(0, 40000) })
    });
  } catch {
    throw new Error(
      "The request was blocked before reaching the server. This is usually CORS — restart the backend after updating main.py."
    );
  }

  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    if (response.status === 503) {
      throw new Error("No API key configured on the server. Check your .env file.");
    }
    if (response.status === 502) {
      throw new Error(
        "The model provider rejected the request. Check that your API key is valid and has credit."
      );
    }
    throw new Error(`Analysis service returned ${response.status}. ${detail.slice(0, 120)}`);
  }

  const analysis = await response.json();
  state.policyFindings = analysis.findings;
  state.policySummary = analysis;
  await persist(state);
  return { analysis, result: computeScore(serialize(state)), sourceUrl };
}

/* ---------- Keyboard shortcut ---------- */

chrome.commands.onCommand.addListener(async (command) => {
  if (command !== "toggle-overlay") return;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;
  try {
    await chrome.tabs.sendMessage(tab.id, { type: "PP_TOGGLE_OVERLAY" });
  } catch {
    // No content script on this page (chrome:// pages, the web store, PDFs).
  }
});

/* ---------- Per-install fuzzing salt ---------- */

/**
 * Generated once and never changed.
 *
 * Without a per-install salt, every PrivacyPilot user would distort a given
 * site identically — which is itself a fingerprint. With it, each install is
 * consistent to a site but different from every other user.
 */
chrome.runtime.onInstalled.addListener(() => {
  ensureSalt().catch(() => {});
});

/* ---------- Restore blocking rules on startup ---------- */

chrome.runtime.onStartup.addListener(async () => {
  const hosts = await listBlocked();
  if (hosts.length) await blockHosts(hosts);
});
