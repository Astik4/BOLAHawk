const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, options);
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${options.method || "GET"} ${path} -> ${res.status}: ${body}`);
  }
  return res.json();
}

export const startScan = (targetUrl) =>
  request("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(targetUrl ? { target_url: targetUrl } : {}),
  });

export const getScan = (scanId) => request(`/api/scans/${scanId}`);

export const listScans = () => request("/api/scans");

export const reportPdfUrl = (scanId) => `${API_BASE}/api/scans/${scanId}/report.pdf`;
export const reportHtmlUrl = (scanId) => `${API_BASE}/api/scans/${scanId}/report.html`;
