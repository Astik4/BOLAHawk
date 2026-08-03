const PHASES = [
  "Reseeding target fixtures",
  "Authenticating test identities",
  "Cross-owner BOLA probes",
  "Endpoint matrix sweep",
  "Detection modules + CVSS scoring",
];

/**
 * The backend runs the scan as one opaque task, so this is an honest
 * time-based estimate rather than a live feed — labelled as such so nobody
 * reads it as real telemetry.
 */
export default function ScanProgress({ elapsedSeconds }) {
  const perPhase = 2.5;
  const active = Math.min(PHASES.length - 1, Math.floor(elapsedSeconds / perPhase));
  const pct = Math.min(95, (elapsedSeconds / (perPhase * PHASES.length)) * 100);

  return (
    <div className="progress">
      <div className="progress-bar">
        <i style={{ width: `${pct}%` }} />
      </div>
      <div className="phases">
        {PHASES.map((label, i) => (
          <div key={label} className={`phase ${i < active ? "done" : i === active ? "active" : ""}`}>
            <span className="tick">{i < active ? "✓" : i === active ? "▸" : "·"}</span>
            <span>{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
