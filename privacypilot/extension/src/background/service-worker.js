
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

const BACKEND = "http://127.0.0.1:8000";
const tabs = new Map(); // tabId -> live observation record

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

/* ---------- Tracker observation ---------- */

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) return;
    let requestHost, pageHost;
    try {
      requestHost = new URL(details.url).hostname;
      const path = new URL(details.url).pathname;
      const state = tabs.get(details.tabId);
      if (!state) return;
      pageHost = state.hostname;

      const hit = identify(requestHost, path);
      if (!hit || hit.category === "cdn") return;
      if (!isThirdParty(requestHost, pageHost)) return;
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

chrome.tabs.onRemoved.addListener((tabId) => tabs.delete(tabId));

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
  const { score } = computeScore(serialize(state));
  const color = score >= 80 ? "#22C55E" : score >= 60 ? "#EAB308" : score >= 40 ? "#F97316" : "#EF4444";
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
    const state = getState(sender.tab.id, sender.tab.url ? new URL(sender.tab.url).hostname : "");
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

  if (msg.type === "PP_GET_TAB") {
    (async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab) return respond({ error: "no_tab" });
      const state = tabs.get(tab.id) || blank(tab.url ? new URL(tab.url).hostname : "");
      respond({
        tabId: tab.id,
        url: tab.url,
        state: serialize(state),
        result: computeScore(serialize(state))
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

  if (msg.type === "PP_DOM_SIGNALS" && sender.tab) {
    const state = tabs.get(sender.tab.id);
    if (state) {
      state.domSignals = msg.signals;
      state.url = sender.tab.url;
      state.phishing = analyzePhishing(sender.tab.url || "", msg.signals);
      if (state.phishing) {
        // A credential-harvesting page is a different order of urgency from a
        // tracker, so it gets its own badge treatment.
        chrome.action.setBadgeText({ tabId: sender.tab.id, text: "!" }).catch(() => {});
        chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: "#EF4444" }).catch(() => {});
      }
    }
    return false;
  }

  if (msg.type === "PP_GET_ALERT") {
    (async () => {
      const tabId = sender.tab?.id;
      const state = tabId != null ? tabs.get(tabId) : null;
      if (!state || !state.hostname) return respond({ alert: null });
      const plain = serialize(state);
      respond({
        alert: buildAlert(plain, computeScore(plain)),
        phishing: state.phishing || null
      });
    })();
    return true;
  }

  if (msg.type === "PP_BLOCK") {
    (async () => {
      try {
        respond(await blockHosts(msg.hosts || []));
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

  // Probe first, so a dead backend produces a clear message instead of the
  // browser's generic "Failed to fetch".
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
      // Note: the policy text is sent, the visited URL is not.
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
      throw new Error("The model provider rejected the request. Check that your API key is valid and has credit.");
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

/* ---------- Restore blocking rules on startup ---------- */

chrome.runtime.onStartup.addListener(async () => {
  const hosts = await listBlocked();
  if (hosts.length) await blockHosts(hosts);
});
