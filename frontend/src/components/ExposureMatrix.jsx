import { useMemo } from "react";
import { contextLabel } from "../owasp";

const IDENTITY_ORDER = ["anonymous", "alice_user", "bob_user", "admin_user"];

/**
 * The scanner's whole premise is "same endpoint, different identity" — this
 * shows that matrix directly. Rows are routes, columns are the identities the
 * scanner logged in as, and every cell is the status code that identity got
 * back. Cells the detection modules flagged are painted at their severity.
 */
export default function ExposureMatrix({ scanResults = [], findings = [] }) {
  const { rows, identities } = useMemo(() => {
    const byRoute = new Map();
    const present = new Set();

    for (const r of scanResults) {
      if (!r || r.status_code == null) continue;
      const key = `${r.method} ${r.endpoint}`;
      if (!byRoute.has(key)) byRoute.set(key, { method: r.method, endpoint: r.endpoint, cells: {} });
      byRoute.get(key).cells[r.auth_context] = r.status_code;
      present.add(r.auth_context);
    }

    // Overlay findings so a flagged cell is unmistakable.
    for (const f of findings) {
      const key = `${f.method} ${f.endpoint}`;
      if (!byRoute.has(key)) continue;
      const row = byRoute.get(key);
      row.flags = row.flags || {};
      const prev = row.flags[f.auth_context];
      if (!prev || f.cvss_score > prev.score) {
        row.flags[f.auth_context] = { severity: f.severity, score: f.cvss_score, title: f.title };
      }
    }

    const identities = IDENTITY_ORDER.filter((i) => present.has(i));
    const rows = [...byRoute.values()].sort((a, b) => {
      const af = Object.keys(a.flags || {}).length;
      const bf = Object.keys(b.flags || {}).length;
      return bf - af || a.endpoint.localeCompare(b.endpoint);
    });
    return { rows, identities };
  }, [scanResults, findings]);

  if (!rows.length) return null;

  return (
    <div className="panel">
      <div className="panel-head">
        <h2>Exposure matrix</h2>
        <span className="hint">Every route, tried under every identity</span>
      </div>

      <div className="matrix-scroll">
        <table className="matrix">
          <thead>
            <tr>
              <th>Route</th>
              {identities.map((id) => (
                <th key={id}>{contextLabel(id)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={`${row.method} ${row.endpoint}`}>
                <td className="route">
                  <span className="verb">{row.method}</span>
                  {row.endpoint}
                </td>
                {identities.map((id) => {
                  const status = row.cells[id];
                  const flag = row.flags?.[id];
                  if (status == null) {
                    return <td key={id}><div className="cell">–</div></td>;
                  }
                  const blocked = status === 401 || status === 403;
                  const cls = flag ? `hit ${flag.severity}` : blocked ? "blocked" : "";
                  const tip = flag
                    ? `${flag.title} — CVSS ${flag.score.toFixed(1)}`
                    : blocked
                    ? "Rejected as expected"
                    : `HTTP ${status}`;
                  return (
                    <td key={id}>
                      <div className={`cell ${cls}`} title={tip}>{status}</div>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="matrix-legend">
        <span><i style={{ background: "var(--critical)" }} />Flagged, painted at finding severity</span>
        <span><i style={{ background: "#0e1a17", border: "1px solid #1c3b30" }} />Rejected (401/403)</span>
        <span><i style={{ background: "var(--ink-800)", border: "1px solid var(--line-soft)" }} />Allowed, nothing flagged</span>
      </div>
    </div>
  );
}
