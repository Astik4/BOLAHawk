import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, LabelList } from "recharts";
import { SEVERITIES } from "../owasp";

const COLORS = { Critical: "#f0484f", High: "#f5943c", Medium: "#f2c94c", Low: "#4fb8f0" };

export default function SeverityChart({ groups = [], activeSeverity, onSelectSeverity }) {
  const counts = {};
  for (const g of groups) counts[g.severity] = (counts[g.severity] || 0) + 1;
  const data = SEVERITIES.map((sev) => ({ severity: sev, count: counts[sev] || 0 }));

  return (
    <div className="panel">
      <div className="panel-head">
        <h2>Unique flaws by severity</h2>
        <span className="hint">Click a bar to filter the list below</span>
      </div>
      <ResponsiveContainer width="100%" height={190}>
        <BarChart data={data} margin={{ top: 16, right: 6, left: -24, bottom: 0 }}>
          <XAxis dataKey="severity" stroke="#6f7992" fontSize={11}
                 fontFamily="IBM Plex Mono, monospace" tickLine={false}
                 axisLine={{ stroke: "#232a3a" }} />
          <YAxis stroke="#6f7992" fontSize={11} tickLine={false}
                 axisLine={{ stroke: "#232a3a" }} allowDecimals={false} />
          <Tooltip
            contentStyle={{ background: "#161b25", border: "1px solid #232a3a", borderRadius: 8,
                            fontSize: 12, fontFamily: "IBM Plex Mono, monospace" }}
            labelStyle={{ color: "#e7eaf2" }}
            cursor={{ fill: "rgba(255,255,255,0.035)" }} />
          <Bar dataKey="count" radius={[5, 5, 0, 0]} cursor="pointer"
               onClick={(d) => onSelectSeverity(activeSeverity === d.severity ? "All" : d.severity)}>
            <LabelList dataKey="count" position="top"
                       style={{ fill: "#aab3c6", fontSize: 11, fontFamily: "IBM Plex Mono, monospace" }} />
            {data.map((d) => (
              <Cell key={d.severity} fill={COLORS[d.severity]}
                    opacity={activeSeverity === "All" || activeSeverity === d.severity ? 1 : 0.22} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
