import { useEffect, useState } from "react";
import { api, SCENARIOS, DEVICES } from "./api.js";

const detailOf = (r) => (typeof r.data.detail === "string" ? r.data.detail : r.data.detail?.message || "Request failed");

function Countdown({ seconds, onDone }) {
  const [left, setLeft] = useState(seconds);
  useEffect(() => {
    if (left <= 0) return onDone?.();
    const t = setTimeout(() => setLeft(left - 1), 1000);
    return () => clearTimeout(t);
  }, [left]);
  return (
    <div className="alert bad">
      <b>Account locked - too many violations.</b>
      <div className="countdown">{left}s</div>
      <div style={{ textAlign: "center", fontSize: 12 }}>until the account unlocks</div>
    </div>
  );
}

function Login({ sim, setSim, onAuth, onMfa, onBlocked, notice }) {
  const [mode, setMode] = useState("login");
  const [f, setF] = useState({ username: "", password: "", department: "General" });
  const [err, setErr] = useState("");
  const [lock, setLock] = useState(null);
  const [busy, setBusy] = useState(false);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });

  async function submit() {
    setBusy(true); setErr("");
    if (mode === "register") {
      const r = await api("/auth/register", { method: "POST", body: f, sim });
      setErr(r.ok ? "Account created. You can log in now." : JSON.stringify(r.data.detail));
      if (r.ok) setMode("login");
      return setBusy(false);
    }
    const r = await api("/auth/login", { method: "POST", body: { username: f.username, password: f.password }, sim });
    setBusy(false);
    if (r.ok && r.data.status === "ALLOW") return onAuth(r.data.access_token);
    if (r.ok) return onMfa(r.data);
    const d = r.data.detail;
    if (r.status === 403 && d?.status === "BLOCKED") return onBlocked(d);
    if (r.status === 423) return setLock(d.seconds);
    setErr(detailOf(r));
  }

  return (
    <div className="center">
      <div className="card auth">
        <h1>Adaptive Access</h1>
        <p className="sub">Secure login with location-aware risk assessment</p>
        {notice && <div className="alert warn">{notice}</div>}
        {lock && <Countdown seconds={lock} onDone={() => setLock(null)} />}
        {err && <div className="alert bad">{err}</div>}
        <label>Username</label><input value={f.username} onChange={set("username")} />
        <label>Password</label>
        <input type="password" value={f.password} onChange={set("password")} onKeyDown={(e) => e.key === "Enter" && submit()} />
        {mode === "register" && (<><label>Department</label>
          <select value={f.department} onChange={set("department")}>
            {["General", "Engineering", "Finance", "Management"].map((d) => <option key={d}>{d}</option>)}
          </select></>)}
        <button className="full" disabled={busy || !!lock} onClick={submit}>
          {mode === "login" ? "Authenticate Access" : "Create account"}
        </button>
        <div className="link" onClick={() => setMode(mode === "login" ? "register" : "login")}>
          {mode === "login" ? "No identity? Provision access" : "Back to login"}
        </div>
        <div className="sim">
          <label>Threat simulator (demo)</label>
          <select value={sim.scenario} onChange={(e) => setSim({ ...sim, scenario: e.target.value })}>
            {Object.entries(SCENARIOS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
          </select>
          <label>Device</label>
          <select value={sim.device} onChange={(e) => setSim({ ...sim, device: e.target.value })}>
            {DEVICES.map((d) => <option key={d}>{d}</option>)}
          </select>
          <p className="sub" style={{ marginTop: 8 }}>Demo users: alice, bob, devuser, manager, admin2, superadmin - password Passw0rd!</p>
        </div>
      </div>
    </div>
  );
}

function Mfa({ info, sim, onAuth, onCancel }) {
  const setup = info.status === "MFA_SETUP_REQUIRED";
  const [qr, setQr] = useState(null);
  const [code, setCode] = useState("");
  const [err, setErr] = useState("");
  useEffect(() => {
    if (setup) api("/auth/mfa/setup", { method: "POST", token: info.mfa_token, sim }).then((r) => r.ok && setQr(r.data));
  }, []);
  async function verify() {
    const r = await api("/auth/mfa/verify", { method: "POST", body: { code }, token: info.mfa_token, sim });
    if (r.ok) onAuth(r.data.access_token); else setErr(detailOf(r));
  }
  return (
    <div className="center"><div className="card auth">
      <h1>{setup ? "Set Up Authenticator" : "Verify Identity"}</h1>
      <p className="sub">{setup ? "Scan the QR code with Google Authenticator or Authy, then enter the 6-digit code."
        : "Unusual login context detected. Enter your authenticator code."}</p>
      {info.reasons?.map((r) => <div className="alert warn" key={r}>{r}</div>)}
      {setup && qr && (<><img className="qr" src={qr.qr} alt="TOTP QR" /><code>{qr.secret}</code></>)}
      {err && <div className="alert bad">{err}</div>}
      <label>Authenticator code</label>
      <input className="code-in" maxLength={6} value={code} placeholder="000000"
        onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} onKeyDown={(e) => e.key === "Enter" && verify()} />
      <button className="full" disabled={code.length !== 6} onClick={verify}>Verify & Authenticate</button>
      <div className="link" onClick={onCancel}>Cancel and return</div>
    </div></div>
  );
}

function Blocked({ info, onBack }) {
  return (
    <div className="center"><div className="card auth">
      <h1 style={{ color: "var(--bad)" }}>Access Blocked</h1>
      <p className="sub">RISK LEVEL: {info.risk_level}</p>
      {info.reasons?.map((r) => <div className="alert bad" key={r}>{r}</div>)}
      <button className="full ghost" onClick={onBack}>Return to Login</button>
    </div></div>
  );
}

function Sparkline({ values }) {
  if (!values.length) return <p className="sub">No data yet</p>;
  const w = 300, h = 80;
  const pts = values.map((v, i) => `${(i / Math.max(values.length - 1, 1)) * w},${h - v * h}`).join(" ");
  return <svg viewBox={`0 0 ${w} ${h}`} width="100%" height="90"><polyline points={pts} fill="none" stroke="#6c6cff" strokeWidth="2" /></svg>;
}

function Dashboard({ token, sim, onLogout }) {
  const [me, setMe] = useState(null);
  const [tab, setTab] = useState("resources");
  const [resources, setResources] = useState([]);
  const [history, setHistory] = useState([]);
  const [msg, setMsg] = useState(null);
  const [admin, setAdmin] = useState({ stats: null, users: [], reqs: [], audit: [] });

  const call = (p, o = {}) => api(p, { token, sim, ...o });
  const isAdmin = me && ["admin", "superuser"].includes(me.role);

  async function refresh() {
    const h = await call("/history"); if (h.ok) setHistory(h.data);
  }
  async function refreshAdmin() {
    const [s, u, r, a] = await Promise.all([call("/admin/stats"), call("/admin/users"), call("/admin/requests"), call("/admin/audit")]);
    setAdmin({ stats: s.data, users: u.data, reqs: r.data, audit: a.data });
  }
  useEffect(() => {
    (async () => {
      const m = await call("/me");
      if (!m.ok) return onLogout(detailOf(m));
      setMe(m.data);
      const r = await call("/resources"); if (r.ok) setResources(r.data);
      refresh();
    })();
  }, []);
  useEffect(() => { if (isAdmin && tab === "admin") refreshAdmin(); }, [tab, isAdmin]);

  async function request(id) {
    const r = await call(`/resources/${id}/access`, { method: "POST" });
    if (r.status === 429) setMsg({ cls: "warn", text: "Adaptive rate limit exceeded - slow down." });
    else if (!r.ok) return onLogout(detailOf(r));
    else {
      const d = r.data;
      setMsg({ cls: d.decision === "GRANTED" ? "ok" : d.decision === "DENIED" ? "bad" : "warn", text: `${d.resource}: ${d.decision} - ${d.reason}` });
      if (d.forced_logout) return onLogout("SECURITY ALERT: repeated violations. Your session was terminated and the account is locked for 60 seconds.");
    }
    refresh(); if (isAdmin && tab === "admin") refreshAdmin();
  }
  async function act(path) { await call(path, { method: "POST" }); refreshAdmin(); }

  if (!me) return <div className="center">Loading...</div>;
  const dist = admin.stats?.distribution || { GRANTED: 0, DENIED: 0 };
  const total = dist.GRANTED + dist.DENIED || 1;

  return (
    <div className="app">
      <div className="top">
        <div><h2>Welcome {me.username}</h2>
          <p className="sub">{me.role} - {me.department} - clearance {me.clearance_level} - login risk {me.risk_score ?? 0}</p></div>
        <button className="ghost" onClick={() => onLogout()}>Sign out</button>
      </div>
      <div className="tabs">
        <button className={tab === "resources" ? "on" : ""} onClick={() => setTab("resources")}>Resources</button>
        {isAdmin && <button className={tab === "admin" ? "on" : ""} onClick={() => setTab("admin")}>Admin Oversight</button>}
      </div>
      {msg && <div className={`alert ${msg.cls}`}>{msg.text}</div>}

      {tab === "resources" && (
        <div className="grid">
          <div className="card"><h3>Sector Resources</h3>
            {resources.map((r) => (
              <div className="res" key={r.id}>
                <div>{r.name}<br /><small>{r.department} - security level {r.sensitivity}</small></div>
                <button className="small" onClick={() => request(r.id)}>Request Access</button>
              </div>))}
          </div>
          <div className="card scroll"><h3>Access History</h3>
            <table><thead><tr><th>Resource</th><th>Time</th><th>Risk</th><th>Verdict</th></tr></thead><tbody>
              {history.filter((h) => h.type === "access").map((h, i) => (
                <tr key={i}><td>{h.resource_name}</td><td>{new Date(h.ts).toLocaleTimeString()}</td><td>{h.risk}</td>
                  <td><span className={`pill ${h.decision}`}>{h.decision}</span></td></tr>))}
            </tbody></table>
          </div>
        </div>
      )}

      {tab === "admin" && isAdmin && (<>
        <div className="stats">
          <div className="card stat"><small>Global access events</small><b>{admin.stats?.total_events ?? 0}</b></div>
          <div className="card stat"><small>Anomalies detected</small><b>{admin.stats?.anomalies ?? 0}</b></div>
          <div className="card stat"><small>Active identities</small><b>{admin.stats?.active_identities ?? 0}</b></div>
        </div>
        <div className="grid">
          <div className="card"><h3>Risk score trajectory</h3><Sparkline values={admin.stats?.risk_trajectory || []} /></div>
          <div className="card"><h3>Access distribution</h3>
            <div className="bar"><div style={{ width: `${(dist.GRANTED / total) * 100}%`, background: "var(--ok)" }} />
              <div style={{ width: `${(dist.DENIED / total) * 100}%`, background: "var(--bad)" }} /></div>
            <small>Granted {dist.GRANTED} - Denied {dist.DENIED}</small></div>
        </div>
        <div className="card scroll" style={{ marginTop: 14 }}><h3>Manager console & global controls</h3>
          <table><thead><tr><th>User</th><th>Role</th><th>Dept</th><th>Status</th><th></th></tr></thead><tbody>
            {admin.users.map((u) => (
              <tr key={u.id}><td>{u.username}</td><td>{u.role}</td><td>{u.department}</td>
                <td><span className={`pill ${u.is_frozen ? "FROZEN" : "ACTIVE"}`}>{u.is_frozen ? "FROZEN" : "ACTIVE"}</span></td>
                <td>{u.id !== me.id && <button className={`small ${u.is_frozen ? "ok" : "bad"}`}
                  onClick={() => act(`/admin/users/${u.id}/${u.is_frozen ? "unfreeze" : "freeze"}`)}>{u.is_frozen ? "Unfreeze" : "Freeze"}</button>}</td></tr>))}
          </tbody></table></div>
        <div className="card scroll" style={{ marginTop: 14 }}><h3>Dual-authorization queue</h3>
          <table><thead><tr><th>Requester</th><th>Resource</th><th>Status</th><th></th></tr></thead><tbody>
            {admin.reqs.map((r) => (
              <tr key={r.id}><td>{r.requester}</td><td>{r.resource}</td><td><span className={`pill ${r.status}`}>{r.status}</span></td>
                <td>{r.status === "pending" && r.requester_id !== me.id && (<>
                  <button className="small ok" onClick={() => act(`/admin/requests/${r.id}/approve`)}>Approve</button>{" "}
                  <button className="small bad" onClick={() => act(`/admin/requests/${r.id}/reject`)}>Reject</button></>)}</td></tr>))}
          </tbody></table></div>
        <div className="card scroll" style={{ marginTop: 14 }}><h3>Audit log</h3>
          <table><thead><tr><th>Time</th><th>User</th><th>Event</th><th>Decision</th><th>Details</th></tr></thead><tbody>
            {admin.audit.map((a, i) => (
              <tr key={i}><td>{new Date(a.ts).toLocaleTimeString()}</td><td>{a.username}</td><td>{a.type}</td>
                <td>{a.decision && <span className={`pill ${a.decision}`}>{a.decision}</span>}</td>
                <td>{a.reason || a.reasons?.join("; ") || a.action || ""}</td></tr>))}
          </tbody></table></div>
      </>)}
    </div>
  );
}

export default function App() {
  const [sim, setSim] = useState({ scenario: "normal", device: "Corporate Laptop" });
  const [screen, setScreen] = useState({ name: "login" });
  const [notice, setNotice] = useState("");
  const toLogin = (n = "") => { setNotice(n); setScreen({ name: "login" }); };

  if (screen.name === "dashboard") return <Dashboard token={screen.token} sim={sim} onLogout={toLogin} />;
  if (screen.name === "mfa") return <Mfa info={screen.info} sim={sim} onAuth={(t) => setScreen({ name: "dashboard", token: t })} onCancel={() => toLogin()} />;
  if (screen.name === "blocked") return <Blocked info={screen.info} onBack={() => toLogin()} />;
  return <Login sim={sim} setSim={setSim} notice={notice}
    onAuth={(t) => setScreen({ name: "dashboard", token: t })}
    onMfa={(info) => setScreen({ name: "mfa", info })}
    onBlocked={(info) => setScreen({ name: "blocked", info })} />;
}
