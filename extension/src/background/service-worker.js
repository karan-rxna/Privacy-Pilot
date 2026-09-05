// PrivacyPilot — MV3 service worker (Stage 1: skeleton).
//
// In later stages this worker owns ALL extension state: per-tab observations,
// the score, blocking rules, and history. For now it only announces itself
// so a successful load is visible in the service worker console.

chrome.runtime.onInstalled.addListener(() => {
  console.log('[PrivacyPilot] skeleton installed');
});