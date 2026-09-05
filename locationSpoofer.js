// PrivacyPilot - location blurring helper.
// Runs in the page's MAIN world, loaded before pageHook.js.
//
// Fixes the original bug: `math.random()` -> `Math.random()`.
// Also blurs properly: a single shared offset applied to both lat and lng
// produced a diagonal shift, and re-rolling the offset on every call let a
// site average the noise away. We now pick one random bearing + distance per
// page load and reuse it, and convert metres to degrees taking latitude into
// account.

(() => {
  "use strict";

  const EARTH_RADIUS_M = 6378137;

  // One fixed offset per page load, so repeated reads cannot be averaged out.
  let cachedOffset = null;

  function offsetFor(radiusMeters) {
    if (!cachedOffset) {
      const bearing = Math.random() * 2 * Math.PI;
      // sqrt keeps the point uniformly distributed over the disc.
      const distance = Math.sqrt(Math.random()) * radiusMeters;
      cachedOffset = {
        north: Math.cos(bearing) * distance,
        east: Math.sin(bearing) * distance
      };
    }
    return cachedOffset;
  }

  /**
   * @param {number} lat
   * @param {number} lng
   * @param {number} radiusMeters  maximum displacement, default ~1 km
   * @returns {{latitude:number, longitude:number}}
   */
  function blurLocation(lat, lng, radiusMeters = 1000) {
    if (typeof lat !== "number" || typeof lng !== "number") {
      return { latitude: lat, longitude: lng };
    }

    const { north, east } = offsetFor(radiusMeters);

    const dLat = (north / EARTH_RADIUS_M) * (180 / Math.PI);
    const cosLat = Math.cos((lat * Math.PI) / 180);
    // Near the poles cosLat -> 0; clamp so we do not divide by ~zero.
    const dLng =
      (east / (EARTH_RADIUS_M * Math.max(Math.abs(cosLat), 1e-6))) *
      (180 / Math.PI);

    let latitude = lat + dLat;
    let longitude = lng + dLng;

    latitude = Math.max(-90, Math.min(90, latitude));
    longitude = ((((longitude + 180) % 360) + 360) % 360) - 180;

    return { latitude, longitude };
  }

  // Handed to pageHook.js, which deletes it immediately so the page cannot see it.
  window.__PrivacyPilotBlurLocation = blurLocation;
})();
