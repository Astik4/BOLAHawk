import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

const SEVERITY_COLORS = {
  Critical: "#e5484d",
  High: "#f2994a",
  Medium: "#f2c94c",
  Low: "#56ccf2",
};

export default function SeverityChart({ summary }) {
  const bySeverity = summary?.by_severity || {};
  const data = ["Critical", "High", "Medium", "Low"].map((sev) => ({
    severity: sev,
    count: bySeverity[sev] || 0,
  }));

  return (
    <div className="chart-panel">
      <h2>Findings by Severity</h2>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
          <XAxis
            dataKey="severity"
            stroke="#7c8496"
            fontSize={12}
            fontFamily="IBM Plex Mono, monospace"
            tickLine={false}
            axisLine={{ stroke: "#232838" }}
          />
          <YAxis stroke="#7c8496" fontSize={12} tickLine={false} axisLine={{ stroke: "#232838" }} allowDecimals={false} />
          <Tooltip
            contentStyle={{ background: "#171b24", border: "1px solid #232838", borderRadius: 6, fontSize: 12 }}
            labelStyle={{ color: "#e8ebf2" }}
            cursor={{ fill: "rgba(255,255,255,0.03)" }}
          />
          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
            {data.map((d) => (
              <Cell key={d.severity} fill={SEVERITY_COLORS[d.severity]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
