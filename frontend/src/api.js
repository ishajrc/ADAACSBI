// Threat simulator: these headers are only honoured when ENABLE_SIMULATION=1 on the backend.
export const SCENARIOS = {
  normal: { label: "Normal login", headers: {} },
  blacklist: { label: "Blacklisted IP", headers: { "X-Simulated-IP": "203.0.113.66" } },
  restricted: { label: "Restricted country (KP)", headers: { "X-Simulated-Country": "KP" } },
  travel: { label: "Impossible travel (US)", headers: { "X-Simulated-Country": "US" } },
};
export const DEVICES = ["Corporate Laptop", "Corporate Desktop", "Personal Laptop", "Personal Phone"];

export async function api(path, { method = "GET", body, token, sim } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (sim) Object.assign(headers, { "X-Device-Type": sim.device }, SCENARIOS[sim.scenario].headers);
  if (token) headers.Authorization = `Bearer ${token}`;
  try {
    const res = await fetch(`/api${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
  } catch {
    return { ok: false, status: 0, data: { detail: "Cannot reach the backend. Is it running on port 8000?" } };
  }
}
