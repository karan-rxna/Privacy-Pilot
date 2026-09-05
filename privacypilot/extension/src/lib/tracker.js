/**
 * Tracker signatures, matched against request hostnames.
 *
 * `weight` is how much a single instance costs the privacy score. Analytics that
 * a site runs on itself is a smaller concern than an ad network that correlates
 * you across every other site it sits on, so cross-site advertising is weighted
 * heaviest.
 *
 * This list is deliberately small and readable. For production you would swap it
 * for the DuckDuckGo Tracker Radar dataset, which carries ownership graphs and
 * prevalence figures for ~5,000 domains.
 */

export const CATEGORIES = {
  advertising: { label: "Advertising", weight: 5, color: "#F87171" },
  analytics: { label: "Analytics", weight: 2, color: "#38BDF8" },
  social: { label: "Social", weight: 4, color: "#C084FC" },
  session: { label: "Session replay", weight: 6, color: "#FB923C" },
  fingerprint: { label: "Fingerprinting", weight: 7, color: "#FBBF24" },
  cdn: { label: "Content delivery", weight: 0, color: "#4ADE80" }
};

const SIGNATURES = [
  ["google-analytics.com", "Google Analytics", "analytics"],
  ["analytics.google.com", "Google Analytics", "analytics"],
  ["googletagmanager.com", "Google Tag Manager", "analytics"],
  ["doubleclick.net", "Google DoubleClick", "advertising"],
  ["googlesyndication.com", "Google AdSense", "advertising"],
  ["googleadservices.com", "Google Ads", "advertising"],
  ["facebook.net", "Meta Pixel", "social"],
  ["facebook.com/tr", "Meta Pixel", "social"],
  ["connect.facebook.net", "Meta Pixel", "social"],
  ["analytics.tiktok.com", "TikTok Pixel", "advertising"],
  ["ads.linkedin.com", "LinkedIn Insight", "advertising"],
  ["px.ads.linkedin.com", "LinkedIn Insight", "advertising"],
  ["static.ads-twitter.com", "X Ads", "advertising"],
  ["snap.licdn.com", "LinkedIn Insight", "advertising"],
  ["criteo.com", "Criteo", "advertising"],
  ["criteo.net", "Criteo", "advertising"],
  ["taboola.com", "Taboola", "advertising"],
  ["outbrain.com", "Outbrain", "advertising"],
  ["adnxs.com", "Xandr", "advertising"],
  ["rubiconproject.com", "Magnite", "advertising"],
  ["pubmatic.com", "PubMatic", "advertising"],
  ["casalemedia.com", "Index Exchange", "advertising"],
  ["openx.net", "OpenX", "advertising"],
  ["amazon-adsystem.com", "Amazon Ads", "advertising"],
  ["scorecardresearch.com", "Comscore", "analytics"],
  ["hotjar.com", "Hotjar", "session"],
  ["fullstory.com", "FullStory", "session"],
  ["clarity.ms", "Microsoft Clarity", "session"],
  ["logrocket.com", "LogRocket", "session"],
  ["mouseflow.com", "Mouseflow", "session"],
  ["smartlook.com", "Smartlook", "session"],
  ["segment.com", "Segment", "analytics"],
  ["segment.io", "Segment", "analytics"],
  ["mixpanel.com", "Mixpanel", "analytics"],
  ["amplitude.com", "Amplitude", "analytics"],
  ["heap.io", "Heap", "analytics"],
  ["heapanalytics.com", "Heap", "analytics"],
  ["matomo.cloud", "Matomo", "analytics"],
  ["plausible.io", "Plausible", "analytics"],
  ["intercom.io", "Intercom", "analytics"],
  ["branch.io", "Branch", "advertising"],
  ["appsflyer.com", "AppsFlyer", "advertising"],
  ["adjust.com", "Adjust", "advertising"],
  ["bugsnag.com", "Bugsnag", "analytics"],
  ["sentry.io", "Sentry", "analytics"],
  ["fingerprintjs.com", "FingerprintJS", "fingerprint"],
  ["fpjs.io", "FingerprintJS", "fingerprint"],
  ["fpapi.io", "FingerprintJS", "fingerprint"],
  ["perimeterx.net", "HUMAN (PerimeterX)", "fingerprint"],
  ["datadome.co", "DataDome", "fingerprint"],
  ["cdn.jsdelivr.net", "jsDelivr", "cdn"],
  ["cdnjs.cloudflare.com", "cdnjs", "cdn"],
  ["unpkg.com", "unpkg", "cdn"],
  ["fonts.gstatic.com", "Google Fonts", "cdn"]
];

/** Returns { name, category } or null. */
export function identify(hostname, path = "") {
  const target = hostname + path;
  for (const [pattern, name, category] of SIGNATURES) {
    if (target.includes(pattern)) return { name, category };
  }
  return null;
}

/** True when the request host is off the page's own registrable domain. */
export function isThirdParty(requestHost, pageHost) {
  if (!requestHost || !pageHost) return false;
  const base = (h) => h.split(".").slice(-2).join(".");
  return base(requestHost) !== base(pageHost);
}
