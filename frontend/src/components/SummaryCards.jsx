export default function SummaryCards({ summary }) {
  const bySeverity = summary?.by_severity || {};
  const cards = [
    { label: "Total", value: summary?.total_findings ?? 0, cls: "" },
    { label: "Critical", value: bySeverity.Critical ?? 0, cls: "Critical" },
    { label: "High", value: bySeverity.High ?? 0, cls: "High" },
    { label: "Medium", value: bySeverity.Medium ?? 0, cls: "Medium" },
    { label: "Low", value: bySeverity.Low ?? 0, cls: "Low" },
    { label: "Highest CVSS", value: (summary?.highest_score ?? 0).toFixed(1), cls: "" },
  ];

  return (
    <div className="summary-row">
      {cards.map((c) => (
        <div key={c.label} className={`summary-card ${c.cls}`}>
          <div className="num">{c.value}</div>
          <div className="label">{c.label}</div>
        </div>
      ))}
    </div>
  );
}
