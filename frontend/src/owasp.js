// Maps each detection module to its OWASP API Security Top 10 (2023) category.
// Keeping this on the client means the dashboard can speak the same language
// an auditor reading the report already knows.
export const OWASP = {
  BOLA: {
    id: "API1:2023",
    name: "Broken Object Level Authorization",
    url: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
  },
  "JWT-FLAWS": {
    id: "API2:2023",
    name: "Broken Authentication",
    url: "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
  },
  "MASS-ASSIGNMENT": {
    id: "API3:2023",
    name: "Broken Object Property Level Authorization",
    url: "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
  },
  "RATE-LIMITING": {
    id: "API4:2023",
    name: "Unrestricted Resource Consumption",
    url: "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
  },
  BFLA: {
    id: "API5:2023",
    name: "Broken Function Level Authorization",
    url: "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
  },
};

export const SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, None: 4 };
export const SEVERITIES = ["Critical", "High", "Medium", "Low"];

export function owaspFor(checkId) {
  return OWASP[checkId] || { id: "—", name: "Uncategorised", url: null };
}

// A single flaw can be proved several times over (one BOLA bug shows up as
// GET + PUT + DELETE, in both directions). Collapsing on check + endpoint +
// method gives the count a remediation owner actually cares about, while the
// raw evidence stays one click away.
export function groupFindings(findings = []) {
  const buckets = new Map();
  for (const f of findings) {
    const key = `${f.check_id}|${f.method}|${f.endpoint}|${f.title}`;
    if (!buckets.has(key)) {
      buckets.set(key, { key, ...f, occurrences: [], contexts: new Set() });
    }
    const b = buckets.get(key);
    b.occurrences.push(f);
    b.contexts.add(f.auth_context);
  }
  return [...buckets.values()]
    .map((b) => ({ ...b, contexts: [...b.contexts] }))
    .sort(
      (a, b) =>
        SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
        b.cvss_score - a.cvss_score
    );
}

export function fingerprint(f) {
  return `${f.check_id}|${f.method}|${f.endpoint}|${f.title}`;
}

// New / still open / fixed, against whichever scan is picked as the baseline.
export function diffScans(current = [], baseline = []) {
  const now = new Set(current.map(fingerprint));
  const then = new Set(baseline.map(fingerprint));
  return {
    added: [...now].filter((k) => !then.has(k)),
    persisting: [...now].filter((k) => then.has(k)),
    resolved: [...then].filter((k) => !now.has(k)),
  };
}

// Weighted exposure index: Critical findings dominate, but volume still moves
// the needle. Capped at 100 so it reads as a posture score, not a raw tally.
export function riskIndex(summary) {
  const s = summary?.by_severity || {};
  const raw =
    (s.Critical || 0) * 10 + (s.High || 0) * 5 + (s.Medium || 0) * 2 + (s.Low || 0) * 1;
  return Math.min(100, Math.round((raw / 60) * 100));
}

export function riskBand(index) {
  if (index >= 75) return { label: "Severe", cls: "Critical" };
  if (index >= 50) return { label: "Elevated", cls: "High" };
  if (index >= 25) return { label: "Moderate", cls: "Medium" };
  if (index > 0) return { label: "Low", cls: "Low" };
  return { label: "Clean", cls: "None" };
}

export const CONTEXT_LABELS = {
  anonymous: "Anonymous",
  alice_user: "Alice",
  bob_user: "Bob",
  admin_user: "Admin",
  forged: "Forged token",
};

export function contextLabel(c) {
  return CONTEXT_LABELS[c] || c;
}
