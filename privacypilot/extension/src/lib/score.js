/**
 * Deterministic scoring.
 *
 * The model never produces the number. Same inputs, same score, every time —
 * which means a judge can re-run the demo and get the same result, and a user
 * can be told exactly why a site lost points.
 *
 * The LLM's output is layered on top as prose, never folded into the arithmetic.
 */

import { CATEGORIES } from "./trackers.js";

const PERMISSION_RISK = {
  microphone: { base: 22, label: "Microphone", expected: ["communication", "media"] },
  camera: { base: 20, label: "Camera", expected: ["communication", "media", "identity"] },
  "screen capture": { base: 24, label: "Screen capture", expected: ["communication"] },
  location: { base: 16, label: "Location", expected: ["maps", "delivery", "weather", "commerce"] },
  "location (high accuracy)": { base: 20, label: "Precise location", expected: ["maps", "delivery"] },
  "location (continuous)": { base: 24, label: "Continuous location", expected: ["maps", "delivery"] },
  notifications: { base: 8, label: "Notifications", expected: ["communication", "news", "commerce"] },
  "clipboard read": { base: 18, label: "Clipboard read", expected: [] },
  "persistent storage": { base: 6, label: "Persistent storage", expected: ["media", "productivity"] },
  bluetooth: { base: 20, label: "Bluetooth", expected: ["hardware"] },
  "usb device": { base: 22, label: "USB device", expected: ["hardware"] }
};

const SITE_TYPES = [
  [/(^|\.)(meet|zoom|teams|whereby|discord|slack)\./, "communication"],
  [/(^|\.)(maps|waze|citymapper)\./, "maps"],
  [/(doordash|ubereats|deliveroo|instacart|grubhub)/, "delivery"],
  [/(weather|accuweather|metoffice)/, "weather"],
  [/(youtube|vimeo|twitch|spotify|netflix|soundcloud)/, "media"],
  [/(amazon|ebay|etsy|shopify|walmart|target|bestbuy|shop)/, "commerce"],
  [/(nytimes|bbc|guardian|reuters|cnn|news)/, "news"],
  [/(docs|notion|figma|linear|asana|trello)/, "productivity"],
  [/(bank|chase|wellsfargo|hsbc|paypal|stripe)/, "finance"]
];

/** Rough site-purpose guess from hostname. Heuristic — the UI labels it as such. */
export function inferSiteType(hostname) {
  for (const [pattern, type] of SITE_TYPES) {
    if (pattern.test(hostname)) return type;
  }
  return "general";
}

function permissionVerdict(detail, siteType) {
  const spec = PERMISSION_RISK[detail] || { base: 10, label: detail, expected: [] };
  const plausible = spec.expected.includes(siteType);
  const penalty = plausible ? Math.round(spec.base * 0.35) : spec.base;

  let level = "low";
  if (penalty >= 18) level = "high";
  else if (penalty >= 9) level = "medium";

  return {
    label: spec.label,
    detail,
    level,
    penalty,
    plausible,
    recommendation: plausible ? (spec.base >= 18 ? "allow_once" : "allow") : "deny"
  };
}

/**
 * @param {object} state per-origin observation record
 * @returns {{score:number, band:string, breakdown:Array, permissions:Array, recommendations:Array}}
 */
export function computeScore(state) {
  const siteType = inferSiteType(state.hostname || "");
  const breakdown = [];

  // --- Permissions ---
  const requested = new Map();
  for (const event of state.events || []) {
    if (event.kind !== "permission" || !event.detail) continue;
    if (!requested.has(event.detail)) requested.set(event.detail, event);
  }
  const permissions = [...requested.keys()].map((d) => permissionVerdict(d, siteType));
  const permissionCost = Math.min(
    40,
    permissions.reduce((sum, p) => sum + p.penalty, 0)
  );
  if (permissionCost) {
    breakdown.push({ label: "Permission requests", cost: permissionCost, count: permissions.length });
  }

  // --- Trackers ---
  const trackers = state.trackers || [];
  const trackerCost = Math.min(
    35,
    trackers.reduce((sum, t) => sum + (CATEGORIES[t.category]?.weight || 2), 0)
  );
  if (trackerCost) {
    breakdown.push({ label: "Third-party trackers", cost: trackerCost, count: trackers.length });
  }

  // --- Fingerprinting ---
  const fpSurfaces = new Set(
    (state.events || []).filter((e) => e.kind === "fingerprint").map((e) => e.detail)
  );
  const fpCost = Math.min(20, fpSurfaces.size * 6);
  if (fpCost) {
    breakdown.push({ label: "Fingerprinting signals", cost: fpCost, count: fpSurfaces.size });
  }

  // --- Third-party cookies ---
  const cookieCost = Math.min(15, Math.round((state.thirdPartyCookies || 0) * 1.5));
  if (cookieCost) {
    breakdown.push({
      label: "Third-party cookies",
      cost: cookieCost,
      count: state.thirdPartyCookies
    });
  }

  // --- Policy findings (from the model, but mapped through a fixed table) ---
  const findings = state.policyFindings || {};
  let policyCost = 0;
  if (findings.sellsData === true) policyCost += 12;
  if (findings.sharesWithAdvertisers === true) policyCost += 8;
  if (findings.retentionIndefinite === true) policyCost += 6;
  if (findings.noOptOut === true) policyCost += 4;
  policyCost = Math.min(25, policyCost);
  if (policyCost) breakdown.push({ label: "Privacy policy terms", cost: policyCost, count: null });

  const score = Math.max(
    0,
    100 - permissionCost - trackerCost - fpCost - cookieCost - policyCost
  );

  let band = "Strong privacy practices";
  if (score < 40) band = "Heavy data collection";
  else if (score < 60) band = "Notable data collection";
  else if (score < 80) band = "Moderate data collection";

  return {
    score,
    band,
    siteType,
    breakdown,
    permissions,
    recommendations: buildRecommendations({ permissions, trackers, fpSurfaces, siteType })
  };
}

/** Why a specific permission is worth denying, in the user's terms. */
const DENIAL_RATIONALE = {
  notifications:
    "Notification permission is durable and is commonly reused later for re-engagement marketing.",
  "clipboard read":
    "Clipboard read exposes whatever you last copied, which is often a password or an address.",
  microphone: "Audio capture is not part of this kind of site's normal operation.",
  camera: "Video capture is not part of this kind of site's normal operation."
};

function buildRecommendations({ permissions, trackers, fpSurfaces, siteType }) {
  const out = [];
  const readable = siteType === "general" ? "this kind of site" : `a ${siteType} site`;

  for (const p of permissions) {
    // Only ever recommend against a permission the verdict already rated as
    // unnecessary — otherwise the panel contradicts itself.
    if (p.recommendation === "deny") {
      out.push({
        action: "deny",
        title: `Deny ${p.label.toLowerCase()}`,
        body:
          DENIAL_RATIONALE[p.detail] ||
          `${readable.charAt(0).toUpperCase() + readable.slice(1)} does not normally need this. Denying it should not break the page.`
      });
    } else if (p.detail.startsWith("location (high")) {
      out.push({
        action: "downgrade",
        title: "Share approximate location instead",
        body: "This site asked for high-accuracy GPS. City-level location is enough for what it does."
      });
    }
  }

  const adTrackers = trackers.filter((t) => t.category === "advertising" || t.category === "social");
  if (adTrackers.length >= 3) {
    out.push({
      action: "block",
      title: "Block third-party cookies for this site",
      body: `${adTrackers.length} advertising or social trackers are loading. They correlate this visit with your activity on other sites.`
    });
  }

  const replay = trackers.filter((t) => t.category === "session");
  if (replay.length) {
    out.push({
      action: "review",
      title: "Session recording is active",
      body: `${replay.map((t) => t.name).join(", ")} can record scrolling, clicks, and text you type into forms before you submit them.`
    });
  }

  if (fpSurfaces.size >= 2) {
    out.push({
      action: "review",
      title: "Consider a private window",
      body: "This site reads canvas, GPU, and font data — a combination used to re-identify you without cookies."
    });
  }

  if (!out.length) {
    out.push({
      action: "none",
      title: "Nothing to change here",
      body: "No unnecessary permissions and no high-impact trackers detected on this page."
    });
  }

  return out;
}
