import { useEffect, useRef, useState } from "react";
import { startScan, getScan, listScans, reportPdfUrl, reportHtmlUrl } from "./api";
import SummaryCards from "./components/SummaryCards";
import SeverityChart from "./components/SeverityChart";
import FindingsTable from "./components/FindingsTable";

export default function App() {
  const [targetUrl, setTargetUrl] = useState("");
  const [scan, setScan] = useState(null);
  const [history, setHistory] = useState([]);
  const [error, setError] = useState(null);
  const pollRef = useRef(null);

  const refreshHistory = async () => {
    try {
      setHistory(await listScans());
    } catch (e) {
      // history is a convenience, not worth surfacing an error banner for
    }
  };

  useEffect(() => {
    refreshHistory();
  }, []);

  const pollScan = (scanId) => {
    clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const updated = await getScan(scanId);
        setScan(updated);
        if (updated.status !== "running") {
          clearInterval(pollRef.current);
          refreshHistory();
        }
      } catch (e) {
        setError(e.message);
        clearInterval(pollRef.current);
      }
    }, 1000);
  };

  const handleRunScan = async () => {
    setError(null);
    try {
      const { scan_id } = await startScan(targetUrl.trim() || undefined);
      const initial = await getScan(scan_id);
      setScan(initial);
      pollScan(scan_id);
    } catch (e) {
      setError(e.message);
    }
  };

  const isRunning = scan?.status === "running";
  const result = scan?.result;

  return (
    <div className="app">
      <div className="app-header">
        <div>
          <h1>BOLAHawk</h1>
          <div className="subtitle">automated OWASP API Top 10 scanner</div>
        </div>
        <div className="scan-control">
          <input
            className="target-input"
            placeholder="http://127.0.0.1:5000 (default)"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            disabled={isRunning}
          />
          <button className="btn" onClick={handleRunScan} disabled={isRunning}>
            {isRunning ? "Scanning…" : "Run Scan"}
          </button>
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {scan && (
        <div className="status-line" style={{ marginBottom: 20 }}>
          <span className={`status-dot ${scan.status}`} />
          scan {scan.scan_id.slice(0, 8)} — {scan.status}
          {scan.status === "failed" && ` (${scan.error})`}
          {scan.status === "completed" && (
            <>
              <a className="btn secondary" style={{ padding: "3px 10px", fontSize: 11 }}
                 href={reportPdfUrl(scan.scan_id)} target="_blank" rel="noreferrer">
                Download PDF
              </a>
              <a className="btn secondary" style={{ padding: "3px 10px", fontSize: 11 }}
                 href={reportHtmlUrl(scan.scan_id)} target="_blank" rel="noreferrer">
                View HTML Report
              </a>
            </>
          )}
        </div>
      )}

      {result ? (
        <>
          <SummaryCards summary={result.summary} />
          <SeverityChart summary={result.summary} />
          <FindingsTable findings={result.findings} />
        </>
      ) : (
        !isRunning && (
          <div className="empty-state">
            No scan results yet. Click "Run Scan" to audit the target API.
          </div>
        )
      )}

      {history.length > 0 && (
        <div className="findings-section">
          <h2>Recent Scans</h2>
          {history.slice(0, 5).map((s) => (
            <div
              key={s.scan_id}
              className="finding-card"
              style={{ cursor: "pointer" }}
              onClick={async () => setScan(await getScan(s.scan_id))}
            >
              <div className="finding-row" style={{ gridTemplateColumns: "90px 1fr 220px" }}>
                <span className={`status-dot ${s.status}`} />
                <span className="finding-title">{s.scan_id.slice(0, 8)}</span>
                <span className="finding-endpoint">{new Date(s.started_at).toLocaleString()}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
