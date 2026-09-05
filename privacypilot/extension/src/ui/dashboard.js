const $ = (id) => document.getElementById(id);
const EMPTY_DASH = "—";

document.body.classList.add("dashboard-transition");
setTimeout(() => {
  document.body.classList.remove("dashboard-transition");
  document.body.classList.add("dashboard-active", "dashboard-ready");
}, 1450);

function scoreColor(score) {
  if (score >= 80) return "#62E5AB";
  if (score >= 60) return "#FFD36E";
  if (score >= 40) return "#BD7BFF";
  return "#FF759D";
}

function median(values) {
  if (!values.length) return null;

  const sorted = [...values].sort((first, second) => first - second);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2
    ? sorted[middle]
    : Math.round((sorted[middle - 1] + sorted[middle]) / 2);
}

function animateNumber(id, nextValue, duration = 700) {
  const node = $(id);
  const previousValue = Number(node.dataset.value || 0);
  if (previousValue === nextValue) return;

  const startedAt = performance.now();
  const tick = (now) => {
    const progress = Math.min(1, (now - startedAt) / duration);
    const easedProgress = 1 - Math.pow(1 - progress, 3);
    node.textContent = Math.round(previousValue + (nextValue - previousValue) * easedProgress);
    if (progress < 1) requestAnimationFrame(tick);
  };

  node.dataset.value = String(nextValue);
  requestAnimationFrame(tick);
}

function renderBarChart(rows, maxValue) {
  const limit = maxValue || Math.max(1, ...rows.map((row) => row.value));

  return rows.map((row) => `
    <div style="margin-bottom:10px">
      <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
        <span>${row.label}</span>
        <span class="mono" style="color:var(--ink-dim)">${row.value}</span>
      </div>
      <div style="height:6px;border-radius:3px;background:rgba(96,205,255,0.1);overflow:hidden">
        <div style="height:100%;width:${(row.value / limit) * 100}%;background:${row.color || "var(--blue)"};transition:width 500ms cubic-bezier(0.2,0.8,0.2,1)"></div>
      </div>
    </div>`).join("");
}

function renderSparkline(history) {
  const scores = history.slice(-12).map((entry) => entry.score);
  if (scores.length < 2) return `<span style="color:var(--ink-faint)">${EMPTY_DASH}</span>`;

  const width = 68;
  const height = 18;
  const step = width / (scores.length - 1);
  const path = scores.map((score, index) => {
    const command = index ? "L" : "M";
    const x = (index * step).toFixed(1);
    const y = (height - (score / 100) * height).toFixed(1);
    return `${command}${x},${y}`;
  }).join(" ");

  return `
    <svg width="${width}" height="${height}" style="vertical-align:middle">
      <path d="${path}" fill="none" stroke="${scoreColor(scores[scores.length - 1])}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`;
}

function renderSummary(sites) {
  const scores = sites.map((site) => site.score);
  const medianScore = median(scores);
  const trackerTotal = sites.reduce((total, site) => total + (site.trackers?.length || 0), 0);

  animateNumber("siteCount", sites.length);
  animateNumber("avgScore", medianScore);
  $("avgScore").style.color = scoreColor(medianScore);
  animateNumber("trackerTotal", trackerTotal);
  animateNumber("riskyCount", scores.filter((score) => score < 50).length);
}

function renderScoreDistribution(scores, siteCount) {
  const bands = [
    { label: "80–100", matches: (score) => score >= 80, color: "#62E5AB" },
    { label: "60–79", matches: (score) => score >= 60 && score < 80, color: "#FFD36E" },
    { label: "40–59", matches: (score) => score >= 40 && score < 60, color: "#BD7BFF" },
    { label: "20–39", matches: (score) => score >= 20 && score < 40, color: "#FF759D" },
    { label: "0–19", matches: (score) => score < 20, color: "#FF4D87" }
  ];

  $("dist").innerHTML = renderBarChart(
    bands.map((band) => ({
      label: band.label,
      value: scores.filter(band.matches).length,
      color: band.color
    })),
    siteCount
  );
}

function renderTopTrackers(sites) {
  const counts = {};
  for (const site of sites) {
    const names = new Set((site.trackers || []).map((tracker) => tracker.name));
    for (const name of names) counts[name] = (counts[name] || 0) + 1;
  }

  const topTrackers = Object.entries(counts)
    .sort(([, firstCount], [, secondCount]) => secondCount - firstCount)
    .slice(0, 8);

  $("topTrackers").innerHTML = topTrackers.length
    ? renderBarChart(topTrackers.map(([label, value]) => ({ label, value })))
    : `<p style="color:var(--ink-faint);font-size:12px">No trackers recorded yet.</p>`;
}

function renderSiteTable(sites) {
  $("siteTable").innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Site</th><th>Assessment</th><th style="text-align:right">Trackers</th>
          <th style="text-align:right">Trend</th><th style="text-align:right">Score</th>
        </tr>
      </thead>
      <tbody>
        ${sites.slice(0, 25).map((site) => `
          <tr>
            <td>${site.hostname}</td>
            <td style="color:var(--ink-dim)">${site.band}</td>
            <td class="num">${site.trackers?.length || 0}</td>
            <td class="num">${renderSparkline(site.history || [])}</td>
            <td class="num" style="color:${scoreColor(site.score)};font-size:14px">${site.score}</td>
          </tr>`).join("")}
      </tbody>
    </table>`;
}

function renderHeatmap(sites) {
  $("heat").innerHTML = sites.map((site) => {
    const trackerCount = site.trackers?.length || 0;
    const color = trackerCount === 0 ? "#34255D"
      : trackerCount <= 3 ? "#7161FF"
      : trackerCount <= 8 ? "#FFD36E"
      : "#FF759D";
    return `<i style="background:${color}" title="${site.hostname} — ${trackerCount} trackers, score ${site.score}"></i>`;
  }).join("");
}

function render(sites) {
  if (!sites.length) {
    document.querySelector(".wrap").insertAdjacentHTML("beforeend", `
      <div class="card empty-state">
        <strong>No sites analysed yet</strong>
        Browse a few pages with the extension enabled, then come back.
      </div>`);
    return;
  }

  const scores = sites.map((site) => site.score);
  renderSummary(sites);
  renderScoreDistribution(scores, sites.length);
  renderTopTrackers(sites);
  renderSiteTable(sites);
  renderHeatmap(sites);
}

$("clearBtn").addEventListener("click", async () => {
  if (!confirm("Delete all locally stored analysis? This cannot be undone.")) return;
  await chrome.storage.local.clear();
  location.reload();
});

chrome.runtime.sendMessage({ type: "PP_ALL_SITES" }, (response) => {
  render(response?.sites || []);
});
