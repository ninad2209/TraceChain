import React from 'react';

function fmt(iso) {
  if (!iso) return '--:--:--';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '--:--:--';
  return d.toLocaleTimeString([], { hour12: false });
}

const Pill = ({ level, children }) => (
  <span className={`pill pill-${String(level).toLowerCase()}`}>{children || level}</span>
);

export default function IncidentPanel({ results, status, isSimulated, onInspect, onViewGraph }) {
  const chain = results
    .filter((r) => r.in_chain)
    .sort((a, b) => (a.create_time || '').localeCompare(b.create_time || '') || a.pid - b.pid);
  const alerts = results.filter((r) => r.threat_level !== 'LOW' && !r.is_isolated);

  // Calm state: nothing suspicious
  if (chain.length === 0 && alerts.length === 0) {
    return (
      <section className="incident incident-ok">
        <div className="incident-head">
          <div>
            <div className="incident-title">No active incidents</div>
            <div className="incident-sub">
              Every process on this system looks normal. Press Simulate Attack to see how TraceChain
              explains a suspicious chain.
            </div>
          </div>
          <Pill level="ok">ALL CLEAR</Pill>
        </div>
      </section>
    );
  }

  // Alerts without a full chain (for example a single medium-risk process)
  if (chain.length === 0) {
    const top = [...alerts].sort((a, b) => b.risk_score - a.risk_score).slice(0, 3);
    return (
      <section className="incident incident-med">
        <div className="incident-head">
          <div>
            <div className="incident-title">{alerts.length} process{alerts.length > 1 ? 'es' : ''} need a look</div>
            <div className="incident-sub">No linked attack chain was found, but these processes triggered rules.</div>
          </div>
          <Pill level="medium">ELEVATED</Pill>
        </div>
        <div className="timeline">
          {top.map((r) => (
            <div className="tl-row" key={`${r.pid}-${r.create_time}`}>
              <div className="tl-badge tl-dot" />
              <div className="tl-time">{fmt(r.create_time)}</div>
              <div className="tl-body">
                <div className="tl-main">{r.name} <span className="muted mono">PID {r.pid}</span></div>
                <div className="tl-why">{r.reasons[0]}</div>
              </div>
              <Pill level={r.threat_level}>{r.risk_score}</Pill>
              <button className="btn btn-ghost" onClick={() => onInspect(r)}>Inspect</button>
            </div>
          ))}
        </div>
      </section>
    );
  }

  // Full chain
  const chainPids = new Set(chain.map((c) => c.pid));
  const highCount = chain.filter((c) => c.threat_level === 'HIGH' && !c.is_isolated).length;
  const topRisk = [...chain].sort((a, b) => b.risk_score - a.risk_score)[0];
  const net = chain
    .flatMap((c) => (c.breakdown || []).filter((f) => f.rule_id === 'R003'))
    .map((f) => f.text.split(': ').pop())[0];
  const resolved = highCount === 0;

  let step = 0;
  const rows = chain.map((c) => {
    const isRoot = !chainPids.has(c.ppid);
    if (!isRoot) step += 1;
    return { c, isRoot, step };
  });

  return (
    <section className={`incident ${resolved ? 'incident-ok' : 'incident-high'}`}>
      <div className="incident-head">
        <div>
          <div className="incident-title">
            {resolved ? 'Incident contained' : 'Suspicious process chain detected'}
            {isSimulated && <span className="muted"> (simulation)</span>}
          </div>
          <div className="incident-sub">
            {chain.length} linked processes{!resolved && `, ${highCount} high-risk`}.
            {net && <> The chain ends with a connection to <span className="mono">{net}</span>.</>}
          </div>
        </div>
        <Pill level={resolved ? 'ok' : status === 'ELEVATED' ? 'medium' : 'high'}>
          {resolved ? 'ISOLATED' : status}
        </Pill>
      </div>

      <div className="timeline">
        {rows.map(({ c, isRoot, step: n }) => {
          const why = (c.breakdown || []).filter((f) => f.rule_id !== 'R011').slice(0, 2);
          return (
            <div className="tl-row" key={`${c.pid}-${c.create_time}`} style={{ opacity: c.is_isolated ? 0.55 : 1 }}>
              {isRoot ? <div className="tl-badge tl-dot" title="Starting point" /> : <div className="tl-badge">{n}</div>}
              <div className="tl-time mono">{fmt(c.create_time)}</div>
              <div className="tl-body">
                <div className="tl-main">
                  {isRoot
                    ? <>{c.name} <span className="muted">(starting point)</span></>
                    : <><span className="muted">{c.parent_name || 'unknown'}</span> started <strong>{c.name}</strong></>}
                  {c.is_isolated && <span className="muted"> · isolated</span>}
                </div>
                {why.map((f, i) => (
                  <div className="tl-why" key={i}>{f.text}</div>
                ))}
              </div>
              <Pill level={c.threat_level}>{c.risk_score}</Pill>
              <button className="btn btn-ghost" onClick={() => onInspect(c)}>Inspect</button>
            </div>
          );
        })}
      </div>

      <div className="incident-foot">
        <span className="muted">
          Numbers match the arrows on the graph. Recommended: review the highest-risk process, then isolate it.
        </span>
        <div className="btn-row">
          <button className="btn btn-ghost" onClick={onViewGraph}>Open attack graph</button>
          <button className="btn btn-primary" onClick={() => onInspect(topRisk)}>Review {topRisk.name}</button>
        </div>
      </div>
    </section>
  );
}