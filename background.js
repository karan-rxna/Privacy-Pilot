// PrivacyPilot - service worker.
// The original was a single console.log with no listeners, so nothing
// connected the content scripts to storage or to any UI.

import { Storage } from "./storage.js";
import { calculateRisk, riskColor } from "./riskEngine.js";

const RULESET_ID = "trackers";

chrome.runtime.onInstalled.addListener(async () => {
  const settings = await Storage.getSettings();
  await applyBlocking(settings.blocking);
});

chrome.runtime.onStartup.addListener(async () => {
  const settings = await Storage.getSettings();
  await applyBlocking(settings.blocking);
});

async function applyBlocking(enabled) {
  try {
    await chrome.declarativeNetRequest.updateEnabledRulesets(
      enabled
        ? { enableRulesetIds: [RULESET_ID] }
        : { disableRulesetIds: [RULESET_ID] }
    );
  } catch (e) {
    console.warn("[PrivacyPilot] could not toggle ruleset:", e);
  }
}

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch (_) {
    return null;
  }
}

async function scoreForSite(site) {
  if (!site) return 100;
  const events = await Storage.getEventsForSite(site);
  const phishing = await Storage.getPhishing(site);
  return calculateRisk(events, phishing ? phishing.findings : []);
}

async function refreshBadge(tabId, site) {
  if (typeof tabId !== "number" || tabId < 0) return;
  const score = await scoreForSite(site);
  try {
    await chrome.action.setBadgeText({ tabId, text: site ? String(score) : "" });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: riskColor(score) });
  } catch (_) {
    /* tab closed */
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    switch (message && message.type) {
      case "event": {
        // Trust the sender's URL, not whatever the page claimed.
        const site = hostOf(sender.url || "") || message.event.site;
        await Storage.addEvent({ ...message.event, site });
        await refreshBadge(sender.tab && sender.tab.id, site);
        sendResponse({ ok: true });
        break;
      }

      case "phishing": {
        const site = hostOf(sender.url || "") || message.site;
        await Storage.setPhishing(site, message.findings);
        await refreshBadge(sender.tab && sender.tab.id, site);
        sendResponse({ ok: true });
        break;
      }

      case "getState": {
        const tab = message.tabId
          ? await chrome.tabs.get(message.tabId).catch(() => null)
          : null;
        const site = tab ? hostOf(tab.url || "") : null;
        const [settings, events, phishing] = await Promise.all([
          Storage.getSettings(),
          site ? Storage.getEventsForSite(site) : Promise.resolve([]),
          site ? Storage.getPhishing(site) : Promise.resolve(null)
        ]);
        const findings = phishing ? phishing.findings : [];
        sendResponse({
          site,
          settings,
          events,
          findings,
          score: calculateRisk(events, findings),
          blocked: await blockedCount(message.tabId)
        });
        break;
      }

      case "setSettings": {
        const settings = await Storage.setSettings(message.patch || {});
        if ("blocking" in (message.patch || {})) {
          await applyBlocking(settings.blocking);
        }
        sendResponse({ ok: true, settings });
        break;
      }

      case "clear": {
        await Storage.clearEvents();
        sendResponse({ ok: true });
        break;
      }

      default:
        sendResponse({ ok: false, error: "unknown message" });
    }
  })().catch((e) => {
    console.warn("[PrivacyPilot] message handler failed:", e);
    try {
      sendResponse({ ok: false, error: String(e) });
    } catch (_) {
      /* channel already closed */
    }
  });

  // Keep the message channel open for the async response above.
  return true;
});

async function blockedCount(tabId) {
  if (typeof tabId !== "number") return 0;
  try {
    const res = await chrome.declarativeNetRequest.getMatchedRules({ tabId });
    return (res && res.rulesMatchedInfo && res.rulesMatchedInfo.length) || 0;
  } catch (_) {
    return 0;
  }
}

// Keep the badge in step as the user moves around.
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  if (tab) refreshBadge(tabId, hostOf(tab.url || ""));
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && tab.url) {
    refreshBadge(tabId, hostOf(tab.url));
  }
});
