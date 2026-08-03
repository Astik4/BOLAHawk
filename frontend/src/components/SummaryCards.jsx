import { riskBand, SEVERITIES } from "../owasp";

function RiskGauge({ index, band }) {
  const r = 26;
  const c = 2 * Math.PI * r;
  const stroke = {
    Critical: "var(--critical)", High: "var(--high)", Medium: "var(--medium)",
    Low: "var(--low)", None: "var(--ok)",
  }[band.cls];

  return (
    <svg width="64" height="64" viewBox="0 0 64 64" role="img" aria-label={`Exposure index ${index} of 100`}>
      <circle cx="32" cy="32" r={r} fill="none" stroke="var(--line)" strokeWidth="5" />
      <circle cx="32" cy="32" r={r} fill="none" stroke={stroke} strokeWidth="5" strokeLinecap="round"
              strokeDasharray={c} strokeDashoffset={c - (c * index) / 100}
              transform="rotate(-90 32 32)"
              style={{ transition: "stroke-dashoffset .7s cubic-bezier(.2,.8,.2,1)" }} />
      <text x="32" y="37" textAnchor="middle" fill="var(--text)"
            fontFamily="var(--font-display)" fontSize="18" fontWeight="700">{index}</text>
    </svg>
  );
}

/**
 * Counts here are *unique flaws*, not raw evidence records — one BOLA bug
 * proved six different ways is one thing to fix, not six. The raw total is
 * kept visible underneath so the two numbers can never look contradictory.
 */
export default function SummaryCards({ groups = [], rawTotal = 0, filter, onFilterChange }) {
  const bySev = {};
  for (const g of groups) bySev[g.severity] = (bySev[g.severity] || 0) + 1;

  const weighted =
    (bySev.Critical || 0) * 10 + (bySev.High || 0) * 5 + (bySev.Medium || 0) * 2 + (bySev.Low || 0);
  const index = Math.min(100, Math.round((weighted / 40) * 100));
  const band = riskBand(index);

  return (
    <div className="summary-grid">
      <div className="gauge-card">
        <RiskGauge index={index} band={band} />
        <div className="gauge-meta">
          <div className={`band ${band.cls}`}>{band.label}</div>
          <div className="cap">Exposure index</div>
        </div>
      </div>

      <button className={`stat ${filter === "All" ? "on" : ""}`} onClick={() => onFilterChange("All")}>
        <div className="num">{groups.length}</div>
        <div className="lbl">Unique flaws</div>
        <div className="lbl" style={{ marginTop: 2 }}>{rawTotal} evidence records</div>
      </button>

      {SEVERITIES.map((sev) => (
        <button key={sev} className={`stat ${sev} ${filter === sev ? "on" : ""}`}
                onClick={() => onFilterChange(filter === sev ? "All" : sev)}>
          <div className="num">{bySev[sev] ?? 0}</div>
          <div className="lbl">{sev}</div>
        </button>
      ))}
    </div>
  );
}
