import { formatTimestamp, scanLabel } from "../utils";

export default function ScanHistory({ history, currentId, onSelect }) {
  if (!history.length) return null;

  return (
    <div className="panel">
      <div className="panel-head">
        <h2>Scan history</h2>
        <span className="hint">Pick a scan to load its findings and compare</span>
      </div>
      {history.slice(0, 8).map((s, i) => {
        const prev = history[i + 1];
        const now = s.result?.summary?.total_findings;
        const before = prev?.result?.summary?.total_findings;
        const delta = now != null && before != null ? now - before : null;
        return (
          <button
            key={s.scan_id}
            className={`history-row ${currentId === s.scan_id ? "on" : ""}`}
            onClick={() => onSelect(s.scan_id)}
          >
            <span className={`dot ${s.status}`} />
            <span className="label">{scanLabel(s)}</span>
            <span className="url">{s.target_url}</span>
            <span className="when">{formatTimestamp(s.started_at)}</span>
            <span className="delta">
              <span>{now != null ? `${now} findings` : s.status}</span>
              {delta !== null && delta !== 0 && (
                <span className={delta > 0 ? "up" : "down"}>
                  {delta > 0 ? `▲ ${delta}` : `▼ ${Math.abs(delta)}`}
                </span>
              )}
              {delta === 0 && <span className="same">no change</span>}
            </span>
          </button>
        );
      })}
    </div>
  );
}
