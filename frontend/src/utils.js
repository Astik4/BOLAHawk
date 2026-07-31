export function scanLabel(scan) {
  return scan.scan_number ? `Scan #${scan.scan_number}` : "Scan";
}

export function formatTimestamp(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatElapsed(startedAtIso, now) {
  const started = new Date(startedAtIso).getTime();
  const seconds = Math.max(0, Math.round((now - started) / 1000));
  return `${seconds}s`;
}
