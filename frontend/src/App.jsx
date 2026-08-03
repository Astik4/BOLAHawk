import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { startScan, getScan, listScans, reportPdfUrl, reportHtmlUrl } from "./api";
import { scanLabel, formatTimestamp, formatElapsed, elapsedSeconds, duration, downloadJson } from "./utils";
import { groupFindings, diffScans, fingerprint } from "./owasp";
import SummaryCards from "./components/SummaryCards";
import SeverityChart from "./components/SeverityChart";
import ExposureMatrix from "./components/ExposureMatrix";
import FindingsTable from "./components/FindingsTable";
import ScanProgress from "./components/ScanProgress";
import ScanHistory from "./components/ScanHistory";

function Mark() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 2 4 5.2v6.1c0 4.7 3.2 8.9 8 10.7 4.8-1.8 8-6 8-10.7V5.2L12 2Z"
            stroke="var(--accent)" strokeWidth="1.6" strokeLinejoin="round" />
      <path d="M8.6 12.1 11 14.5l4.6-4.7" stroke="var(--accent)" strokeWidth="1.8"
            strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export default function App() {
  const [targetUrl, setTargetUrl] = useState("");
  const [scan, setScan] = useState(null);
  const [history, setHistory] = useState([]);
  const [error, setError] = useState(null);
  const [severityFilter, setSeverityFilter] = useState("All");
  const [now, setNow] = useState(Date.now());
  const [toast, setToast] = useState(null);
  const pollRef = useRef(null);
  const tickRef = useRef(null);

  const notify = useCallback((msg) => {
    setToast(msg);
    setTimeout(() => setToast(null), 1600);
  }, []);

  const refreshHistory = useCallback(async () => {
    try {
      setHistory(await listScans());
    } catch {
      /* history is a convenience — not worth a banner */
    }
  }, []);

  useEffect(() => { refreshHistory(); }, [refreshHistory]);

  useEffect(() => {
    if (scan?.status === "running") {
      tickRef.current = setInterval(() => setNow(Date.now()), 500);
    } else {
      clearInterval(tickRef.current);
    }
    return () => clearInterval(tickRef.current);
  }, [scan?.status]);

  const pollScan = (scanId) => {
    clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const updated = await getScan(scanId);
        setScan(updated);
        if (updated.status !== "running") {
          clearInterval(pollRef.current);
          refreshHistory();
          notify(
            updated.status === "completed"
              ? `Scan finished — ${updated.result?.summary?.total_findings ?? 0} findings`
              : "Scan failed"
          );
        }
      } catch (e) {
        setError(e.message);
        clearInterval(pollRef.current);
      }
    }, 1000);
  };

  const handleRunScan = async () => {
    setError(null);
    setSeverityFilter("All");
    try {
      const { scan_id } = await startScan(targetUrl.trim() || undefined);
      const initial = await getScan(scan_id);
      setScan(initial);
      pollScan(scan_id);
    } catch (e) {
      setError(e.message);
    }
  };

  const selectScan = async (id) => {
    try {
      setScan(await getScan(id));
      setSeverityFilter("All");
    } catch (e) {
      setError(e.message);
    }
  };

  useEffect(() => () => { clearInterval(pollRef.current); clearInterval(tickRef.current); }, []);

  const isRunning = scan?.status === "running";
  const result = scan?.result;
  const findings = result?.findings || [];
  const grouped = useMemo(() => groupFindings(findings), [findings]);

  // Compare against the scan immediately before this one, if there is one.
  const baseline = useMemo(() => {
    const idx = history.findIndex((h) => h.scan_id === scan?.scan_id);
    return idx >= 0 ? history[idx + 1] : null;
  }, [history, scan?.scan_id]);

  const delta = useMemo(() => {
    if (!baseline?.result?.findings) return null;
    return diffScans(findings, baseline.result.findings);
  }, [findings, baseline]);

  const newKeys = useMemo(() => new Set(delta?.added || []), [delta]);

  const spine = useMemo(() => {
    const s = result?.summary?.by_severity || {};
    const total = Object.values(s).reduce((a, b) => a + b, 0) || 1;
    return ["Critical", "High", "Medium", "Low"].map((sev) => ({ sev, pct: ((s[sev] || 0) / total) * 100 }));
  }, [result]);

  return (
    <div className="app">
      <header className="masthead">
        <div className="brand">
          <div className="brand-mark"><Mark /></div>
          <div>
            <h1>BOLAHawk</h1>
            <div className="tagline">Automated OWASP API Security Top 10 auditor</div>
          </div>
        </div>

        <div className="scan-control">
          <input
            className="target-input"
            placeholder="Target API base URL — defaults to the bundled test target"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !isRunning && handleRunScan()}
            disabled={isRunning}
            aria-label="Target API base URL"
          />
          <button className="btn" onClick={handleRunScan} disabled={isRunning}>
            {isRunning ? `Scanning ${formatElapsed(scan.started_at, now)}` : "Run scan"}
          </button>
        </div>
      </header>

      <div className="spine" aria-hidden="true">
        {result
          ? spine.map((s) => <span key={s.sev} className={s.sev} style={{ flexGrow: s.pct }} />)
          : null}
      </div>

      {error && <div className="banner">{error}</div>}

      {scan && (
        <div className="status-strip">
          <span className={`dot ${scan.status}`} />
          <strong>{scanLabel(scan)}</strong>
          <span className="sep">/</span>
          <span>{scan.target_url}</span>
          <span className="sep">/</span>
          <span>{formatTimestamp(scan.started_at)}</span>
          {scan.finished_at && (
            <>
              <span className="sep">/</span>
              <span>took {duration(scan.started_at, scan.finished_at)}</span>
            </>
          )}
          {scan.status === "failed" && <span style={{ color: "var(--critical)" }}>{scan.error}</span>}

          <span className="spacer" />

          {delta && (
            <span className="delta">
              <span className="up">{delta.added.length} new</span>
              <span className="same">{delta.persisting.length} still open</span>
              <span className="down">{delta.resolved.length} fixed</span>
            </span>
          )}

          {scan.status === "completed" && (
            <>
              <a className="btn ghost" href={reportPdfUrl(scan.scan_id)} target="_blank" rel="noreferrer">
                PDF report
              </a>
              <a className="btn ghost" href={reportHtmlUrl(scan.scan_id)} target="_blank" rel="noreferrer">
                HTML report
              </a>
              <button
                className="btn ghost"
                onClick={() => { downloadJson(`bolahawk-${scan.scan_number || "scan"}.json`, result); notify("Findings exported"); }}
              >
                Export JSON
              </button>
            </>
          )}
        </div>
      )}

      {isRunning && <ScanProgress elapsedSeconds={elapsedSeconds(scan.started_at, now)} />}

      {result ? (
        <>
          <SummaryCards
            groups={grouped}
            rawTotal={findings.length}
            filter={severityFilter}
            onFilterChange={setSeverityFilter}
          />
          <SeverityChart
            groups={grouped}
            activeSeverity={severityFilter}
            onSelectSeverity={setSeverityFilter}
          />
          <ExposureMatrix
            scanResults={[...(result.scan_results || []), ...(result.bola_probe_results || [])]}
            findings={findings}
          />
          <FindingsTable
            findings={findings}
            filter={severityFilter}
            onFilterChange={setSeverityFilter}
            newKeys={newKeys}
            onCopied={() => notify("Copied to clipboard")}
          />
        </>
      ) : (
        !isRunning && (
          <div className="empty">
            <strong>No scan loaded</strong>
            Run a scan against the target API, or pick one from the history below.
          </div>
        )
      )}

      <ScanHistory history={history} currentId={scan?.scan_id} onSelect={selectScan} />

      <footer className="foot">
        <span>Findings scored with the CVSS v3.1 base formula, computed from the FIRST.org specification.</span>
        <span>Scan only systems you are authorised to test.</span>
      </footer>

      {toast && <div className="toast" role="status">{toast}</div>}
    </div>
  );
}
