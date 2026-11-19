export function scanLabel(scan) {
  return scan?.scan_number ? `Scan #${scan.scan_number}` : "Scan";
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
  if (!startedAtIso) return "0s";
  const started = new Date(startedAtIso).getTime();
  if (isNaN(started)) return "0s";
  const seconds = Math.max(0, Math.round((now - started) / 1000));
  return `${seconds}s`;
}

export function elapsedSeconds(startedAtIso, now) {
  if (!startedAtIso) return 0;
  const started = new Date(startedAtIso).getTime();
  if (isNaN(started)) return 0;
  return Math.max(0, (now - started) / 1000);
}

export function duration(startIso, endIso) {
  if (!startIso || !endIso) return null;
  const start = new Date(startIso).getTime();
  const end = new Date(endIso).getTime();
  if (isNaN(start) || isNaN(end)) return null;
  const secs = Math.max(0, (end - start) / 1000);
  return `${secs.toFixed(1)}s`;
}

export function downloadJson(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
