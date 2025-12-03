// ---------- Short helper ----------
const $ = (id) => document.getElementById(id);

// Global state
let lastScanResult = null;
let allLogs = [];

// =====================================================
// DRAG & DROP + FILE SELECTION
// =====================================================

function showSelected(file) {
  if (!file) return;
  $('dropHint').classList.add('hidden');
  $('selectedWrap').classList.remove('hidden');
  $('selectedName').textContent = file.name;
}

function clearSelected() {
  $('fileInput').value = "";
  $('selectedWrap').classList.add('hidden');
  $('dropHint').classList.remove('hidden');
}

function wireDropZone() {
  const dz = $('dropZone');
  const input = $('fileInput');
  const browseBtn = $('browseBtn');
  const clearBtn = $('clearFile');

  // clicking "Browse Files"
  browseBtn.addEventListener('click', () => input.click());

  // when file picked via dialog
  input.addEventListener('change', () => {
    if (input.files && input.files[0]) showSelected(input.files[0]);
  });

  // drag over/leave
  dz.addEventListener('dragover', (e) => {
    e.preventDefault();
    dz.classList.add('dragover');
  });
  dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));

  // drop
  dz.addEventListener('drop', (e) => {
    e.preventDefault();
    dz.classList.remove('dragover');
    const files = e.dataTransfer.files;
    if (!files || !files.length) return;
    input.files = files;   // attach to the real input
    showSelected(files[0]);
  });

  // clear button
  clearBtn.addEventListener('click', clearSelected);
}

// =====================================================
// SCAN & PROGRESS
// =====================================================

function setVerdictUI(verdict, confidencePct, fname, riskBand) {
  const box = $('resultBox');
  $('fileName').textContent = fname;

  $('verdictLine').classList.remove('hidden');
  $('confidenceLine').classList.remove('hidden');
  $('verdictText').textContent = verdict;
  $('confidenceText').textContent = confidencePct + "%";
  $('riskBand').textContent = riskBand ? "• " + riskBand : "";

  box.className = "result-box " + (verdict === "Malicious" ? "result-box-bad" : "result-box-safe");
}

function showProgressStep(text) {
  const el = $('scan-progress');
  el.classList.remove('hidden');
  el.textContent = text;
}

function hideProgress() {
  const el = $('scan-progress');
  el.classList.add('hidden');
}

function showError(msg) {
  alert(msg);
}

function renderResults(data) {
  const { filename, verdict, final_prob, risk_band, reasons } = data;
  const confPct = final_prob !== undefined ? Math.round(final_prob * 1000) / 10 : 0;
  const fname = filename || "(no name)";
  const band = risk_band || "";

  setVerdictUI(verdict || "Unknown", Math.round(confPct), fname, band);

  const details = $('scan-result-details');
  details.classList.remove('hidden');

  // Main lines
  $('result-final').textContent =
    `Final decision: ${verdict} (${confPct.toFixed(1)}% malicious)`;
  $('result-band').textContent = `Risk level: ${band || "Unknown"}`;

  // Short friendly summary instead of model breakdown
  const summaryEl = $('result-summary');
  let summaryText = "";

  if (verdict === "Malicious") {
    summaryText = "This file shows strong indicators associated with ransomware-like behaviour.";
  } else if (band === "Caution") {
    summaryText = "Some characteristics appear unusual. The file may require further review.";
  } else {
    summaryText = "No significant indicators of ransomware were detected in this file.";
  }
  summaryEl.textContent = summaryText;

  // Reasons
  const list = $('reasonsList');
  list.innerHTML = "";
  if (Array.isArray(reasons) && reasons.length) {
    reasons.forEach((r) => {
      const li = document.createElement("li");
      li.textContent = r;
      list.appendChild(li);
    });
    $('reasonsLine').classList.remove('hidden');
  } else {
    $('reasonsLine').classList.add('hidden');
  }
}


async function startScan(file) {
  const fd = new FormData();
  fd.append("file", file);

  const name = (file.name || "").toLowerCase();

  // Decide endpoint based on extension
  let endpoint = "/scan";  // default: feature file (CSV/XLSX)
  let stages = [
    "Uploading & analyzing...",
    "Analyzing static features...",
    "Analyzing behavioral patterns...",
    "Combining results & generating explanation...",
  ];

  if (name.endsWith(".exe") || name.endsWith(".dll")) {
    endpoint = "/scan_exe";  // EXE route
    stages = [
      "Uploading executable...",
      "Analyzing PE static features...",
      "Generating explanation & risk band...",
    ];
  }

  let progressStage = 0;
  showProgressStep(stages[0]);

  const interval = setInterval(() => {
    progressStage = (progressStage + 1) % stages.length;
    showProgressStep(progressStage < stages.length ? stages[progressStage] : stages[0]);
  }, 700);

  try {
    const res = await fetch(endpoint, { method: "POST", body: fd });
    const data = await res.json().catch(() => null);

    clearInterval(interval);
    hideProgress();

    if (!res.ok || !data) {
      showError(data?.detail || "Scan failed.");
      return;
    }

    lastScanResult = data;
    $('download-report-btn').disabled = false;

    renderResults(data);
  } catch (e) {
    clearInterval(interval);
    hideProgress();
    showError("Network error during scan.");
  }
}


// =====================================================
// DOWNLOAD REPORT (PDF)
// =====================================================

async function downloadCurrentReport() {
  if (!lastScanResult) return;

  try {
    const res = await fetch("/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(lastScanResult),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showError(err.detail || "Failed to generate report.");
      return;
    }

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `report_${lastScanResult.filename || "scan"}.pdf`;
    a.click();
    window.URL.revokeObjectURL(url);
  } catch (e) {
    showError("Error downloading report.");
  }
}

// =====================================================
// HISTORY MODAL + FILTER + DETAIL
// =====================================================

function openHistory() {
  $('historyModal').classList.add("open");
  document.body.style.overflow = "hidden";
}
function closeHistoryModal() {
  $('historyModal').classList.remove("open");
  document.body.style.overflow = "";
}

function openHistoryDetailModal() {
  $('historyDetailModal').classList.add('open');
}
function closeHistoryDetailModal() {
  $('historyDetailModal').classList.remove('open');
}

function renderHistoryTable(logs) {
  const tbody = $('historyBody');
  tbody.innerHTML = "";

  logs.forEach((log) => {
    const tr = document.createElement("tr");
    tr.className = "hover-row cursor-pointer";

    const ts = log.timestamp ? new Date(log.timestamp).toLocaleString() : "-";
    const pct = typeof log.probability === "number"
      ? (Math.round(log.probability * 1000) / 10) + "%"
      : "-";
    const verdictTxt = log.verdict || "-";
    const badge = `<span class="badge ${verdictTxt.toLowerCase()==='malicious' ? 'badge-bad' : 'badge-good'}">${verdictTxt}</span>`;

    tr.innerHTML = `
      <td>${ts}</td>
      <td>${log.filename || "-"}</td>
      <td>${badge}</td>
      <td>${pct}</td>
    `;

    tr.onclick = () => openHistoryDetail(log);
    tbody.appendChild(tr);
  });
}

function applyHistoryFilter(value) {
  const now = new Date();
  const filtered = allLogs.filter((log) => {
    if (!log.timestamp) return true;
    const t = new Date(log.timestamp);
    const diffDays = (now - t) / (1000 * 60 * 60 * 24);

    if (value === '7d')   return diffDays <= 7;
    if (value === '30d')  return diffDays <= 30;
    if (value === '365d') return diffDays <= 365;
    return true; // 'all'
  });

  renderHistoryTable(filtered);
}

async function loadHistory() {
  const res = await fetch("/logs");
  const rows = await res.json();

  allLogs = Array.isArray(rows) ? rows : [];
  const historyEmpty = $('historyEmpty');

  if (!allLogs.length) {
    historyEmpty.style.display = "block";
  } else {
    historyEmpty.style.display = "none";
  }

  renderHistoryTable(allLogs);
  openHistory();
}

function openHistoryDetail(log) {
  $('detail-filename').textContent = log.filename || "-";
  $('detail-verdict').textContent = log.verdict || "-";
  $('detail-prob').textContent =
    typeof log.probability === "number"
      ? (log.probability * 100).toFixed(1) + "%"
      : "-";
  $('detail-time').textContent = log.timestamp
    ? new Date(log.timestamp).toLocaleString()
    : "-";

  // Minimal payload (for report from history)
  const payload = {
    filename: log.filename,
    verdict: log.verdict,
    final_prob: log.probability,
    risk_band:
      log.probability >= 0.7 ? "High Risk"
      : log.probability >= 0.3 ? "Caution"
      : "Safe",
    debug: {},
    reasons: [],
  };

  $('history-download-btn').onclick = async () => {
    try {
      const res = await fetch("/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        showError(err.detail || "Failed to generate report.");
        return;
      }
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `report_${log.filename || "scan"}.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (e) {
      showError("Error downloading report from history.");
    }
  };

  openHistoryDetailModal();
}

// =====================================================
// TABS: SCAN / EDUCATION
// =====================================================

function wireTabs() {
  const tabScan = $('tab-scan');
  const tabEdu = $('tab-education');
  const scanPanel = $('scan-panel');
  const eduPanel = $('education-panel');

  function setActive(btn) {
    [tabScan, tabEdu].forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
  }

  tabScan.addEventListener('click', () => {
    setActive(tabScan);
    scanPanel.classList.remove('hidden');
    eduPanel.classList.add('hidden');
  });

  tabEdu.addEventListener('click', () => {
    setActive(tabEdu);
    scanPanel.classList.add('hidden');
    eduPanel.classList.remove('hidden');
  });
}

// =====================================================
// INITIAL WIRING (on page load)
// =====================================================

window.addEventListener('DOMContentLoaded', () => {
  wireDropZone();
  wireTabs();

  // Scan button
  $('scanBtnMain').addEventListener('click', () => {
    const input = $('fileInput');
    if (!input.files.length) {
      alert("Please choose a file to scan (CSV/XLSX or EXE).");
      return;
    }

    // reset result UI before scanning
    $('resultBox').className = "result-box result-box-idle";
    $('fileName').textContent = "Scanning...";
    ['verdictLine','confidenceLine','reasonsLine'].forEach(id => $(id).classList.add('hidden'));
    $('reasonsList').innerHTML = "";
    $('scan-result-details').classList.add('hidden');
    $('download-report-btn').disabled = true;
    showProgressStep("Uploading & analyzing...");

    startScan(input.files[0]);
  });

  // Download report for last scan
  $('download-report-btn').addEventListener('click', downloadCurrentReport);

  // History main button
  $('historyBtn').addEventListener('click', loadHistory);

  // Close history modals
  $('closeHistory').addEventListener('click', closeHistoryModal);
  $('historyModal').addEventListener('click', (e) => {
    if (e.target === $('historyModal')) closeHistoryModal();
  });

  $('closeHistoryDetail').addEventListener('click', closeHistoryDetailModal);
  $('historyDetailModal').addEventListener('click', (e) => {
    if (e.target === $('historyDetailModal')) closeHistoryDetailModal();
  });

  // History filter
  $('history-filter').addEventListener('change', (e) => {
    applyHistoryFilter(e.target.value);
  });
});
