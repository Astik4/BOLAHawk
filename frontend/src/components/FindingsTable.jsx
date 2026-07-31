import { useState } from "react";

function FindingCard({ f }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`finding-card ${f.severity}`}>
      <div className="finding-row" onClick={() => setOpen(!open)}>
        <span className={`sev-badge ${f.severity}`}>{f.severity}</span>
        <span className="finding-title">{f.title}</span>
        <span className="finding-endpoint">{f.method} {f.endpoint}</span>
        <span className="finding-score">{f.cvss_score.toFixed(1)}</span>
        <span className={`chevron ${open ? "open" : ""}`}>&#9656;</span>
      </div>
      {open && (
        <div className="finding-detail">
          <div className="field-label">Check</div>
          <div>{f.check_id} &middot; context: {f.auth_context}</div>

          <div className="field-label">Description</div>
          <div>{f.description}</div>

          <div className="field-label">Evidence</div>
          <code>{f.evidence}</code>

          <div className="field-label">Remediation</div>
          <div>{f.remediation}</div>

          <div className="field-label">CVSS Vector</div>
          <code>{f.cvss_vector}</code>
        </div>
      )}
    </div>
  );
}

export default function FindingsTable({ findings }) {
  const [filter, setFilter] = useState("All");
  const severities = ["All", "Critical", "High", "Medium", "Low"];
  const visible = filter === "All" ? findings : findings.filter((f) => f.severity === filter);

  return (
    <div className="findings-section">
      <h2>
        Findings ({visible.length})
        <span style={{ float: "right", display: "flex", gap: 6 }}>
          {severities.map((s) => (
            <button
              key={s}
              className={`btn secondary`}
              style={{
                padding: "4px 10px",
                fontSize: 11,
                borderColor: filter === s ? "var(--accent)" : "var(--border)",
                color: filter === s ? "var(--accent)" : "var(--muted)",
              }}
              onClick={() => setFilter(s)}
            >
              {s}
            </button>
          ))}
        </span>
      </h2>
      {visible.length === 0 ? (
        <div className="empty-state">No findings for this filter.</div>
      ) : (
        visible.map((f, i) => <FindingCard key={i} f={f} />)
      )}
    </div>
  );
}
