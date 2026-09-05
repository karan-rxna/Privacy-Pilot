// PrivacyPilot - MAIN world page hook.
//
// This is the fix for the core bug in the original build: the geolocation
// override lived in content.js, which runs in the extension's ISOLATED world.
// That world has its own copy of `navigator`, so patching it there never
// affected the page's own JavaScript and the hook silently never fired.
//
// This file is declared with "world": "MAIN" at document_start, so it patches
// the real page objects before any page script runs. It has no access to
// chrome.* APIs, so it reports events to content.js via window.postMessage.

(() => {
  "use strict";

  if (window.__privacyPilotHooked) return;
  window.__privacyPilotHooked = true;

  const CHANNEL = "privacypilot";

  // Take the blur helper and hide it from the page.
  const blurLocation = window.__PrivacyPilotBlurLocation;
  try {
    delete window.__PrivacyPilotBlurLocation;
  } catch (_) {
    window.__PrivacyPilotBlurLocation = undefined;
  }

  // Settings arrive from content.js. Defaults are the safe/no-op ones so we
  // never spoof before we know the user asked for it.
  let settings = { blurLocation: false, blurRadiusMeters: 1000 };

  window.addEventListener("message", (e) => {
    if (e.source !== window) return;
    const d = e.data;
    if (!d || d.channel !== CHANNEL || d.direction !== "to-page") return;
    if (d.kind === "settings" && d.settings) {
      settings = { ...settings, ...d.settings };
    }
  });

  // Throttle: one report per event type per site per 5s, so a page polling
  // getCurrentPosition in a loop cannot flood storage.
  const lastReport = new Map();
  function report(type, detail) {
    const now = Date.now();
    const prev = lastReport.get(type) || 0;
    if (now - prev < 5000) return;
    lastReport.set(type, now);

    window.postMessage(
      {
        channel: CHANNEL,
        direction: "to-extension",
        kind: "event",
        event: {
          type,
          site: location.hostname,
          url: location.origin,
          detail: detail || null,
          timestamp: now
        }
      },
      location.origin === "null" ? "*" : location.origin
    );
  }

  // ---------------------------------------------------------------- geolocation
  const geo = navigator.geolocation;
  if (geo) {
    const originalGetCurrentPosition = geo.getCurrentPosition.bind(geo);
    const originalWatchPosition = geo.watchPosition.bind(geo);

    function wrapSuccess(success) {
      if (typeof success !== "function") return success;
      return function (position) {
        if (!settings.blurLocation || !blurLocation || !position || !position.coords) {
          return success(position);
        }
        const { latitude, longitude } = blurLocation(
          position.coords.latitude,
          position.coords.longitude,
          settings.blurRadiusMeters
        );
        // GeolocationPosition/Coordinates are read-only, so hand back a plain
        // object with the same shape.
        const coords = {
          latitude,
          longitude,
          accuracy: Math.max(position.coords.accuracy || 0, settings.blurRadiusMeters),
          altitude: position.coords.altitude,
          altitudeAccuracy: position.coords.altitudeAccuracy,
          heading: position.coords.heading,
          speed: position.coords.speed
        };
        return success({ coords, timestamp: position.timestamp });
      };
    }

    geo.getCurrentPosition = function (success, error, options) {
      report("location", { api: "getCurrentPosition" });
      return originalGetCurrentPosition(wrapSuccess(success), error, options);
    };

    // The original build never patched watchPosition, so any site could log
    // your position continuously without PrivacyPilot noticing.
    geo.watchPosition = function (success, error, options) {
      report("location", { api: "watchPosition" });
      return originalWatchPosition(wrapSuccess(success), error, options);
    };
  }

  // ------------------------------------------------------- camera / microphone
  const md = navigator.mediaDevices;
  if (md && typeof md.getUserMedia === "function") {
    const originalGetUserMedia = md.getUserMedia.bind(md);
    md.getUserMedia = function (constraints) {
      const c = constraints || {};
      if (c.video) report("camera", { api: "getUserMedia" });
      if (c.audio) report("microphone", { api: "getUserMedia" });
      return originalGetUserMedia(constraints);
    };
  }

  if (typeof navigator.getDisplayMedia === "function" || (md && md.getDisplayMedia)) {
    const target = md && md.getDisplayMedia ? md : navigator;
    const originalGetDisplayMedia = target.getDisplayMedia.bind(target);
    target.getDisplayMedia = function (constraints) {
      report("screen", { api: "getDisplayMedia" });
      return originalGetDisplayMedia(constraints);
    };
  }

  // ------------------------------------------------------------------ clipboard
  const clip = navigator.clipboard;
  if (clip) {
    ["readText", "read"].forEach((name) => {
      if (typeof clip[name] !== "function") return;
      const original = clip[name].bind(clip);
      clip[name] = function (...args) {
        report("clipboard", { api: name });
        return original(...args);
      };
    });
  }

  // ------------------------------------------------------- canvas fingerprinting
  if (window.HTMLCanvasElement) {
    const proto = HTMLCanvasElement.prototype;
    const originalToDataURL = proto.toDataURL;
    proto.toDataURL = function (...args) {
      // Tiny canvases used for real drawing are common; fingerprinting scripts
      // read pixels back off an offscreen canvas, so flag the read itself.
      report("canvas", { api: "toDataURL" });
      return originalToDataURL.apply(this, args);
    };

    if (window.CanvasRenderingContext2D) {
      const ctxProto = CanvasRenderingContext2D.prototype;
      const originalGetImageData = ctxProto.getImageData;
      ctxProto.getImageData = function (...args) {
        report("canvas", { api: "getImageData" });
        return originalGetImageData.apply(this, args);
      };
    }
  }

  // --------------------------------------------------------------- notifications
  if (window.Notification && typeof Notification.requestPermission === "function") {
    const originalRequestPermission = Notification.requestPermission.bind(Notification);
    Notification.requestPermission = function (...args) {
      report("notifications", { api: "requestPermission" });
      return originalRequestPermission(...args);
    };
  }
})();
