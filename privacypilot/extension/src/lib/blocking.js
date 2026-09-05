/**
 * Enforcement.
 *
 * Two separate mechanisms, because Chrome treats network requests and device
 * permissions completely differently:
 *
 *  - declarativeNetRequest blocks outbound requests to tracker hosts. Rules are
 *    declarative, so the browser enforces them without waking the extension.
 *  - contentSettings sets the camera/mic/location default for one origin, which
 *    is the same thing the padlock menu does, applied programmatically.
 *
 * Rule IDs are derived from a hash of the hostname so the same host always maps
 * to the same ID. That makes "block" idempotent and "unblock" trivial.
 */

const RULE_ID_BASE = 1000;
const RULE_ID_RANGE = 90000;

function ruleId(hostname) {
  let hash = 0;
  for (let i = 0; i < hostname.length; i++) {
    hash = (hash * 31 + hostname.charCodeAt(i)) | 0;
  }
  return RULE_ID_BASE + (Math.abs(hash) % RULE_ID_RANGE);
}

export async function blockHosts(hostnames) {
  const unique = [...new Set(hostnames)].filter(Boolean);
  if (!unique.length) return { blocked: 0 };

  const rules = unique.map((hostname) => ({
    id: ruleId(hostname),
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: `||${hostname}^`,
      resourceTypes: ["script", "xmlhttprequest", "image", "sub_frame", "ping", "media"]
    }
  }));

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: rules.map((r) => r.id),
    addRules: rules
  });

  const stored = await chrome.storage.local.get("blockedHosts");
  const merged = [...new Set([...(stored.blockedHosts || []), ...unique])];
  await chrome.storage.local.set({ blockedHosts: merged });

  return { blocked: unique.length, total: merged.length };
}

export async function unblockHosts(hostnames) {
  const unique = [...new Set(hostnames)].filter(Boolean);
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: unique.map(ruleId),
    addRules: []
  });

  const stored = await chrome.storage.local.get("blockedHosts");
  const remaining = (stored.blockedHosts || []).filter((h) => !unique.includes(h));
  await chrome.storage.local.set({ blockedHosts: remaining });
  return { total: remaining.length };
}

export async function listBlocked() {
  const stored = await chrome.storage.local.get("blockedHosts");
  return stored.blockedHosts || [];
}

/** Maps our permission labels onto Chrome's contentSettings namespaces. */
const SETTING_FOR = {
  microphone: "microphone",
  camera: "camera",
  location: "location",
  "location (high accuracy)": "location",
  "location (continuous)": "location",
  notifications: "notifications"
};

export async function denyPermission(origin, detail) {
  const setting = SETTING_FOR[detail];
  if (!setting || !chrome.contentSettings?.[setting]) {
    return { ok: false, reason: "Chrome does not expose a setting for this permission." };
  }

  await chrome.contentSettings[setting].set({
    primaryPattern: `${origin}/*`,
    setting: "block"
  });

  return { ok: true, setting };
}
