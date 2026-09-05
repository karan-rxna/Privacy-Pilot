/**
 * PrivacyPilot AI — consent explanations and grant scoping.
 *
 * This module answers one question: when a site asks for a device permission,
 * what do we tell the user, and what does each choice actually mean?
 *
 * Everything here is a lookup, not a generation. The same site type plus the
 * same permission always produces the same explanation, for the same reason the
 * privacy score is arithmetic rather than model output: a user who sees two
 * different explanations for the same situation stops trusting either one.
 */

import { inferSiteType } from "./score.js";

/* ------------------------------------------------------------------ */
/* What each permission actually costs the user, in plain terms        */
/* ------------------------------------------------------------------ */

const CONSEQUENCE = {
  microphone:
    "Record audio at any time while this tab is open, and reopen the microphone on future visits without asking again.",
  camera:
    "Capture video at any time while this tab is open, and reopen the camera on future visits without asking again.",
  "screen capture":
    "Record everything on your screen, including windows belonging to other applications.",
  location:
    "Read your position while this tab is open, and read it again on every future visit without asking.",
  "location (high accuracy)":
    "Read your position to within a few metres — precise enough to identify a building, not just a neighbourhood.",
  "location (continuous)":
    "Track your position continuously, updating as you move, for as long as this tab stays open.",
  "clipboard read":
    "Read whatever you last copied. That is frequently a password, an address, or a card number.",
  notifications:
    "Send you messages after you leave. Notification grants are durable and are commonly reused for marketing.",
  "persistent storage":
    "Keep data on your device that ordinary browsing-data clearing will not remove.",
  bluetooth: "Communicate with devices you have paired to this machine.",
  "usb device": "Communicate directly with hardware you plug in."
};

/**
 * Human-readable names. The internal detail strings are keys, not copy —
 * "wants your location (high accuracy)" reads like a log line.
 */
const DISPLAY_NAME = {
  "location (high accuracy)": "precise location",
  "location (continuous)": "continuous location",
  "clipboard read": "clipboard",
  "screen capture": "screen",
  "persistent storage": "permanent storage",
  "usb device": "USB access"
};

/**
 * Why a site type would plausibly need a permission.
 *
 * A missing entry means "we know of no ordinary reason", which is the honest
 * default — it is a statement about our table, not a claim about the site.
 */
const PLAUSIBLE_REASON = {
  "communication:microphone": "Voice and video calling is this site's core function.",
  "communication:camera": "Video calling is this site's core function.",
  "communication:screen capture": "Screen sharing is a normal part of a call.",
  "media:microphone": "Recording or voice input is a normal feature here.",
  "media:camera": "Recording is a normal feature here.",
  "maps:location": "Showing where you are is this site's core function.",
  "maps:location (high accuracy)": "Turn-by-turn navigation needs precise position.",
  "maps:location (continuous)": "Navigation needs your position as you move.",
  "delivery:location": "Finding your delivery address is a normal step here.",
  "delivery:location (high accuracy)": "Delivery to a specific address needs precision.",
  "weather:location": "Local forecasts need to know roughly where you are.",
  "commerce:location": "Finding nearby stores or estimating delivery is a normal feature.",
  // Deliberately no "commerce:microphone". Voice search exists on shopping
  // sites but is rare, and this table cannot tell a search box from a checkout
  // script. Granting blanket cover here would excuse exactly the request this
  // feature exists to catch.
  "news:notifications": "Breaking-news alerts are a normal feature.",
  "commerce:notifications": "Order and delivery updates are a normal feature.",
  "communication:notifications": "Message alerts are the point of this kind of site.",
  "productivity:persistent storage": "Offline editing needs data kept on the device.",
  "media:persistent storage": "Offline playback needs data kept on the device.",
  "hardware:bluetooth": "Connecting to a device is this site's stated purpose.",
  "hardware:usb device": "Connecting to hardware is this site's stated purpose."
};

/* ------------------------------------------------------------------ */
/* Grant scopes                                                        */
/* ------------------------------------------------------------------ */

/**
 * Three scopes, and deliberately no fourth.
 *
 * There is no "always allow". A permanent grant is exactly the failure mode
 * this feature exists to fix — a site you visited once two years ago should not
 * still be able to open your camera without asking.
 */
export const SCOPES = {
  deny: {
    id: "deny",
    label: "Deny",
    detail: "The page keeps working.",
    revokeOn: null
  },
  once: {
    id: "once",
    label: "Allow once",
    detail: "Revoked when you close or leave this page.",
    revokeOn: "navigation"
  },
  session: {
    id: "session",
    label: "Allow for this visit",
    detail: "Revoked when every tab for this site is closed.",
    revokeOn: "last-tab-closed"
  }
};

/* ------------------------------------------------------------------ */
/* The explanation                                                     */
/* ------------------------------------------------------------------ */

/**
 * Build everything the consent dialog needs to render.
 *
 * @param {string} hostname   e.g. "shopdeals.example"
 * @param {string} detail     a permission label, e.g. "microphone"
 * @param {string} [script]   URL of the script that made the call
 * @returns {{
 *   hostname: string, detail: string, siteType: string, plausible: boolean,
 *   severity: "high"|"medium", headline: string, verdict: string,
 *   consequence: string, script: string|null, recommended: "deny"|"once"|"session"
 * }}
 */
export function explainRequest(hostname, detail, script) {
  const siteType = inferSiteType(hostname || "");
  const reason = PLAUSIBLE_REASON[`${siteType}:${detail}`];
  const plausible = Boolean(reason);
  const name = DISPLAY_NAME[detail] || detail;

  // Phrase the negative case as a limit on what we know, not a claim about the
  // site. "We know of no reason" is defensible; "this site is malicious" is not.
  const verdict = plausible
    ? reason
    : siteType === "general"
      ? "Nothing on this page suggests a reason for it."
      : `A ${siteType} site does not normally need this.`;

  return {
    hostname,
    detail,
    siteType,
    plausible,
    severity: plausible ? "medium" : "high",
    displayName: name,
    headline: plausible
      ? `${hostname} wants your ${name}`
      : `${hostname} wants your ${name} — this does not look necessary`,
    verdict,
    consequence: CONSEQUENCE[detail] || "Access to a device capability.",
    script: cleanScript(script),
    // Even a plausible request only earns a scoped grant, never a standing one.
    recommended: plausible ? "session" : "deny"
  };
}

/** Trim a script URL down to something a person can read. */
function cleanScript(script) {
  if (!script || script === "inline script") return script || null;
  try {
    const url = new URL(script);
    const file = url.pathname.split("/").filter(Boolean).pop();
    return file || url.hostname;
  } catch {
    return String(script).slice(0, 80);
  }
}

/* ------------------------------------------------------------------ */
/* Deferral policy                                                     */
/* ------------------------------------------------------------------ */

/**
 * Permissions we can hold behind a dialog.
 *
 * Notification.requestPermission is deliberately absent. It requires transient
 * user activation, which expires in a few seconds — by the time an async dialog
 * returns a decision, the activation is gone and the underlying call fails.
 * Notifications are handled through the dashboard instead. Do not "fix" this by
 * adding it to the list.
 */
export const DEFERRABLE = new Set([
  "microphone",
  "camera",
  "screen capture",
  "location",
  "location (high accuracy)",
  "location (continuous)",
  "clipboard read",
  "bluetooth",
  "usb device"
]);

/**
 * How long the page waits for a decision before we give up and allow.
 *
 * Failing open is deliberate. If the service worker is asleep, the overlay
 * failed to mount, or the user simply walked away, a pending promise would hang
 * the site forever. An extension that silently breaks every website is worse
 * than one that occasionally stops protecting.
 */
export const DECISION_TIMEOUT_MS = 8000;
