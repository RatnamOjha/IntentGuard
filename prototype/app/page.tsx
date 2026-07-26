"use client";

import { useMemo, useState } from "react";

type Decision = "Allowed" | "Review" | "Blocked";
type AgentStatus = "Live" | "Revoked";

type Agent = {
  id: string;
  name: string;
  role: string;
  initials: string;
  status: AgentStatus;
  spent: number;
  budget: number;
  permissions: number;
};

type Event = {
  id: string;
  time: string;
  agent: string;
  action: string;
  amount: string;
  decision: Decision;
  reason: string;
  latency: string;
};

const initialAgents: Agent[] = [
  {
    id: "agt_travel_01",
    name: "Atlas",
    role: "Travel concierge",
    initials: "AT",
    status: "Live",
    spent: 48320,
    budget: 100000,
    permissions: 8,
  },
  {
    id: "agt_service_02",
    name: "Nova",
    role: "Service recovery",
    initials: "NV",
    status: "Live",
    spent: 69200,
    budget: 75000,
    permissions: 5,
  },
  {
    id: "agt_benefits_03",
    name: "Orbit",
    role: "Benefits assistant",
    initials: "OR",
    status: "Live",
    spent: 18600,
    budget: 50000,
    permissions: 6,
  },
];

const initialEvents: Event[] = [
  {
    id: "evt_84920",
    time: "14:32:08",
    agent: "Atlas",
    action: "Book flight",
    amount: "₹16,240",
    decision: "Allowed",
    reason: "Within scope and daily cap",
    latency: "6.8 ms",
  },
  {
    id: "evt_84919",
    time: "14:31:54",
    agent: "Nova",
    action: "Reverse service fee",
    amount: "₹4,500",
    decision: "Review",
    reason: "Dual approval required",
    latency: "8.3 ms",
  },
  {
    id: "evt_84918",
    time: "14:31:20",
    agent: "Orbit",
    action: "Submit benefit claim",
    amount: "₹38,000",
    decision: "Blocked",
    reason: "Merchant category not permitted",
    latency: "5.9 ms",
  },
  {
    id: "evt_84917",
    time: "14:30:42",
    agent: "Atlas",
    action: "Reserve hotel",
    amount: "₹9,800",
    decision: "Allowed",
    reason: "Policy travel.v4 matched",
    latency: "7.1 ms",
  },
];

const scenarios = {
  booking: {
    title: "Compliant travel booking",
    agent: "Atlas",
    action: "Book hotel · BOM",
    amount: "₹12,400",
    decision: "Allowed" as Decision,
    reason: "Permission, budget and risk checks passed",
    latency: "6.4 ms",
  },
  cap: {
    title: "Dynamic spend cap breach",
    agent: "Nova",
    action: "Issue service credit",
    amount: "₹18,500",
    decision: "Blocked" as Decision,
    reason: "Would exceed the agent’s ₹75,000 daily cap",
    latency: "5.7 ms",
  },
  permission: {
    title: "Out-of-scope merchant payment",
    agent: "Orbit",
    action: "Pay external merchant",
    amount: "₹31,200",
    decision: "Blocked" as Decision,
    reason: "Action not present in the signed permission lease",
    latency: "5.3 ms",
  },
  approval: {
    title: "High-risk fee reversal",
    agent: "Nova",
    action: "Reverse annual fee",
    amount: "₹9,999",
    decision: "Review" as Decision,
    reason: "Amount exceeds auto-approval threshold",
    latency: "7.8 ms",
  },
};

type ScenarioKey = keyof typeof scenarios;

function currentTime() {
  return new Date().toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export default function Home() {
  const [agents, setAgents] = useState(initialAgents);
  const [events, setEvents] = useState(initialEvents);
  const [scenarioKey, setScenarioKey] = useState<ScenarioKey>("booking");
  const [lastResult, setLastResult] = useState<(typeof scenarios)[ScenarioKey] | null>(
    null,
  );
  const [fleetStopped, setFleetStopped] = useState(false);
  const [showStopConfirm, setShowStopConfirm] = useState(false);
  const [notice, setNotice] = useState("");
  const [activeNav, setActiveNav] = useState("Overview");

  const liveCount = agents.filter((agent) => agent.status === "Live").length;
  const summary = useMemo(
    () => ({
      allowed: events.filter((event) => event.decision === "Allowed").length + 1280,
      blocked: events.filter((event) => event.decision === "Blocked").length + 15,
      review: events.filter((event) => event.decision === "Review").length + 2,
    }),
    [events],
  );

  function addEvent(event: Omit<Event, "id" | "time">) {
    setEvents((current) => [
      {
        ...event,
        id: `evt_${84921 + current.length}`,
        time: currentTime(),
      },
      ...current,
    ]);
  }

  function simulate() {
    const selected = scenarios[scenarioKey];
    const agent = agents.find((item) => item.name === selected.agent);
    const result =
      fleetStopped || agent?.status === "Revoked"
        ? {
            ...selected,
            decision: "Blocked" as Decision,
            reason: fleetStopped
              ? "Global emergency stop is active"
              : "Agent execution lease has been revoked",
            latency: "2.1 ms",
          }
        : selected;

    setLastResult(result);
    addEvent({
      agent: result.agent,
      action: result.action,
      amount: result.amount,
      decision: result.decision,
      reason: result.reason,
      latency: result.latency,
    });
    setNotice(`Decision ${result.decision.toLowerCase()} and audit event sealed.`);
  }

  function toggleAgent(agentId: string) {
    const target = agents.find((agent) => agent.id === agentId);
    if (!target) return;
    const nextStatus: AgentStatus = target.status === "Live" ? "Revoked" : "Live";
    setAgents((current) =>
      current.map((agent) =>
        agent.id === agentId ? { ...agent, status: nextStatus } : agent,
      ),
    );
    addEvent({
      agent: target.name,
      action: nextStatus === "Revoked" ? "Execution lease revoked" : "Agent restored",
      amount: "—",
      decision: nextStatus === "Revoked" ? "Blocked" : "Allowed",
      reason:
        nextStatus === "Revoked"
          ? "Manual operator intervention"
          : "Operator re-authorized signed lease",
      latency: "1.4 ms",
    });
    setNotice(
      `${target.name} ${nextStatus === "Revoked" ? "revoked" : "restored"} successfully.`,
    );
  }

  function stopFleet() {
    setFleetStopped(true);
    setShowStopConfirm(false);
    setAgents((current) =>
      current.map((agent) => ({ ...agent, status: "Revoked" })),
    );
    addEvent({
      agent: "Entire fleet",
      action: "Emergency stop",
      amount: "—",
      decision: "Blocked",
      reason: "Global kill switch activated by operator",
      latency: "0.9 ms",
    });
    setNotice("Emergency stop propagated to all agents.");
  }

  function restoreFleet() {
    setFleetStopped(false);
    setAgents((current) => current.map((agent) => ({ ...agent, status: "Live" })));
    addEvent({
      agent: "Entire fleet",
      action: "Fleet restored",
      amount: "—",
      decision: "Allowed",
      reason: "Operator re-authorized fleet execution",
      latency: "1.8 ms",
    });
    setNotice("Fleet restored with fresh signed execution leases.");
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            IG
          </span>
          <span>
            <strong>IntentGuard</strong>
            <small>Agent control plane</small>
          </span>
        </div>

        <nav className="main-nav" aria-label="Primary navigation">
          <p className="nav-label">CONTROL</p>
          {["Overview", "Agent fleet", "Policies", "Budgets", "Approvals"].map(
            (item) => (
              <button
                className={activeNav === item ? "nav-item active" : "nav-item"}
                key={item}
                onClick={() => {
                  setActiveNav(item);
                  setNotice(`${item} workspace selected for this prototype.`);
                }}
                type="button"
              >
                <span className="nav-icon" aria-hidden="true">
                  {item === "Overview"
                    ? "⌂"
                    : item === "Agent fleet"
                      ? "◉"
                      : item === "Policies"
                        ? "◇"
                        : item === "Budgets"
                          ? "₹"
                          : "✓"}
                </span>
                {item}
              </button>
            ),
          )}
          <p className="nav-label secondary-label">ASSURANCE</p>
          {["Audit trail", "Integrations"].map((item) => (
            <button
              className={activeNav === item ? "nav-item active" : "nav-item"}
              key={item}
              onClick={() => {
                setActiveNav(item);
                setNotice(`${item} workspace selected for this prototype.`);
              }}
              type="button"
            >
              <span className="nav-icon" aria-hidden="true">
                {item === "Audit trail" ? "≡" : "↗"}
              </span>
              {item}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="integrity-card">
            <span className="integrity-icon" aria-hidden="true">
              ✓
            </span>
            <div>
              <strong>Audit chain verified</strong>
              <small>2,481 events sealed</small>
            </div>
          </div>
          <div className="operator">
            <span className="avatar">RO</span>
            <div>
              <strong>Ratnam Ojha</strong>
              <small>Fleet operator</small>
            </div>
            <span className="more">•••</span>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <p className="eyebrow">GOVERNANCE OVERVIEW</p>
            <h1>Financial agent control room</h1>
          </div>
          <div className="topbar-actions">
            <div className={fleetStopped ? "system-state danger" : "system-state"}>
              <span className="pulse" />
              <span>
                <small>FLEET STATUS</small>
                <strong>{fleetStopped ? "Emergency stop" : "Operational"}</strong>
              </span>
            </div>
            {fleetStopped ? (
              <button className="button primary" onClick={restoreFleet} type="button">
                Restore fleet
              </button>
            ) : (
              <button
                className="button emergency"
                onClick={() => setShowStopConfirm(true)}
                type="button"
              >
                <span aria-hidden="true">■</span> Emergency stop
              </button>
            )}
          </div>
        </header>

        {notice && (
          <div className="notice" role="status">
            <span>✓</span>
            {notice}
            <button onClick={() => setNotice("")} aria-label="Dismiss notice" type="button">
              ×
            </button>
          </div>
        )}

        <section className="hero-status">
          <div className="hero-copy">
            <div className="status-kicker">
              <span className={fleetStopped ? "live-dot stopped" : "live-dot"} />
              REAL-TIME ENFORCEMENT
            </div>
            <h2>
              Every agent action is
              <br />
              <span>bounded before execution.</span>
            </h2>
            <p>
              IntentGuard verifies identity, scope, budget, risk and revocation state
              before a financial connector ever sees the request.
            </p>
          </div>
          <div className="decision-latency">
            <div className="latency-ring">
              <span>p95</span>
              <strong>7.8</strong>
              <small>milliseconds</small>
            </div>
            <div className="latency-copy">
              <strong>Policy decision latency</strong>
              <small>−1.4 ms from last hour</small>
            </div>
          </div>
        </section>

        <section className="metric-grid" aria-label="Fleet metrics">
          <article className="metric-card">
            <span className="metric-icon blue">◉</span>
            <div>
              <p>Protected agents</p>
              <strong>{liveCount}<small> / {agents.length}</small></strong>
              <span className="metric-note">{fleetStopped ? "Fleet halted" : "All connectors healthy"}</span>
            </div>
          </article>
          <article className="metric-card">
            <span className="metric-icon green">✓</span>
            <div>
              <p>Allowed today</p>
              <strong>{summary.allowed.toLocaleString("en-IN")}</strong>
              <span className="metric-note positive">98.6% policy accuracy</span>
            </div>
          </article>
          <article className="metric-card">
            <span className="metric-icon red">×</span>
            <div>
              <p>Blocked today</p>
              <strong>{summary.blocked}</strong>
              <span className="metric-note">₹4.8L exposure prevented</span>
            </div>
          </article>
          <article className="metric-card">
            <span className="metric-icon amber">!</span>
            <div>
              <p>Awaiting review</p>
              <strong>{summary.review}</strong>
              <span className="metric-note warning">Oldest · 3 min</span>
            </div>
          </article>
        </section>

        <section className="work-grid">
          <article className="panel simulator-panel">
            <div className="panel-header">
              <div>
                <span className="panel-kicker">INTERACTIVE DEMO</span>
                <h3>Simulate an agent action</h3>
              </div>
              <span className="sandbox-badge">Safe sandbox</span>
            </div>
            <p className="panel-intro">
              Choose a scenario and watch the governance chain reach a decision.
            </p>
            <label className="field-label" htmlFor="scenario">
              Request scenario
            </label>
            <div className="select-wrap">
              <select
                id="scenario"
                value={scenarioKey}
                onChange={(event) => {
                  setScenarioKey(event.target.value as ScenarioKey);
                  setLastResult(null);
                }}
              >
                {Object.entries(scenarios).map(([key, scenario]) => (
                  <option key={key} value={key}>
                    {scenario.title}
                  </option>
                ))}
              </select>
              <span aria-hidden="true">⌄</span>
            </div>

            <div className="request-preview">
              <div>
                <span>AGENT</span>
                <strong>{scenarios[scenarioKey].agent}</strong>
              </div>
              <div>
                <span>ACTION</span>
                <strong>{scenarios[scenarioKey].action}</strong>
              </div>
              <div>
                <span>AMOUNT</span>
                <strong>{scenarios[scenarioKey].amount}</strong>
              </div>
            </div>

            <div className="policy-chain" aria-label="Policy evaluation sequence">
              {["Identity", "Permission", "Budget", "Risk"].map((step, index) => (
                <div className="chain-step" key={step}>
                  <span>{index + 1}</span>
                  <small>{step}</small>
                  {index < 3 && <i aria-hidden="true">→</i>}
                </div>
              ))}
            </div>

            <button className="evaluate-button" onClick={simulate} type="button">
              Evaluate request <span aria-hidden="true">→</span>
            </button>

            {lastResult && (
              <div className={`result-card ${lastResult.decision.toLowerCase()}`}>
                <div className="result-symbol" aria-hidden="true">
                  {lastResult.decision === "Allowed"
                    ? "✓"
                    : lastResult.decision === "Review"
                      ? "!"
                      : "×"}
                </div>
                <div>
                  <span>DECISION</span>
                  <strong>{lastResult.decision}</strong>
                  <p>{lastResult.reason}</p>
                </div>
                <div className="result-latency">
                  <small>LATENCY</small>
                  <strong>{lastResult.latency}</strong>
                </div>
              </div>
            )}
          </article>

          <article className="panel fleet-panel">
            <div className="panel-header">
              <div>
                <span className="panel-kicker">SIGNED EXECUTION LEASES</span>
                <h3>Agent fleet</h3>
              </div>
              <button
                className="text-button"
                onClick={() => setNotice("Agent fleet workspace selected.")}
                type="button"
              >
                View all →
              </button>
            </div>
            <div className="agent-list">
              {agents.map((agent) => {
                const utilization = Math.round((agent.spent / agent.budget) * 100);
                return (
                  <div className="agent-row" key={agent.id}>
                    <div className={`agent-avatar ${agent.status.toLowerCase()}`}>
                      {agent.initials}
                    </div>
                    <div className="agent-main">
                      <div className="agent-title">
                        <span>
                          <strong>{agent.name}</strong>
                          <small>{agent.role}</small>
                        </span>
                        <span className={`status-pill ${agent.status.toLowerCase()}`}>
                          <i />
                          {agent.status}
                        </span>
                      </div>
                      <div className="budget-line">
                        <span>
                          ₹{agent.spent.toLocaleString("en-IN")}
                          <small> of ₹{agent.budget.toLocaleString("en-IN")}</small>
                        </span>
                        <span>{utilization}%</span>
                      </div>
                      <div className="progress">
                        <span
                          className={utilization > 85 ? "hot" : ""}
                          style={{ width: `${utilization}%` }}
                        />
                      </div>
                      <div className="agent-meta">
                        <span>{agent.permissions} scoped actions</span>
                        <button
                          className={agent.status === "Live" ? "revoke" : "restore"}
                          onClick={() => toggleAgent(agent.id)}
                          type="button"
                        >
                          {agent.status === "Live" ? "Revoke" : "Restore"}
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </article>
        </section>

        <section className="panel events-panel">
          <div className="panel-header">
            <div>
              <span className="panel-kicker">APPEND-ONLY AUDIT STREAM</span>
              <h3>Live decisions</h3>
            </div>
            <div className="stream-status">
              <span className="live-dot" /> Streaming
            </div>
          </div>
          <div className="event-table" role="table" aria-label="Live policy decisions">
            <div className="event-row event-head" role="row">
              <span>TIME / EVENT</span>
              <span>AGENT</span>
              <span>ACTION</span>
              <span>AMOUNT</span>
              <span>DECISION</span>
              <span>LATENCY</span>
            </div>
            {events.slice(0, 6).map((event) => (
              <div className="event-row" role="row" key={event.id}>
                <span>
                  <strong>{event.time}</strong>
                  <small>{event.id}</small>
                </span>
                <span>
                  <strong>{event.agent}</strong>
                </span>
                <span>
                  <strong>{event.action}</strong>
                  <small>{event.reason}</small>
                </span>
                <span>
                  <strong>{event.amount}</strong>
                </span>
                <span>
                  <span className={`decision-pill ${event.decision.toLowerCase()}`}>
                    {event.decision}
                  </span>
                </span>
                <span className="mono">{event.latency}</span>
              </div>
            ))}
          </div>
          <div className="audit-footer">
            <span>
              <i aria-hidden="true">✓</i> SHA-256 chain verified through event{" "}
              {events[0]?.id}
            </span>
            <button
              className="text-button"
              onClick={() => setNotice("Audit export prepared for Splunk.")}
              type="button"
            >
              Export evidence ↗
            </button>
          </div>
        </section>
      </main>

      {showStopConfirm && (
        <div className="modal-backdrop" role="presentation">
          <section
            aria-describedby="stop-description"
            aria-labelledby="stop-title"
            aria-modal="true"
            className="modal"
            role="dialog"
          >
            <div className="modal-alert" aria-hidden="true">
              ■
            </div>
            <p className="eyebrow">HIGH-IMPACT CONTROL</p>
            <h2 id="stop-title">Stop the entire agent fleet?</h2>
            <p id="stop-description">
              All signed execution leases will be revoked immediately. New financial
              actions will fail closed until an operator restores the fleet.
            </p>
            <div className="modal-impact">
              <span>
                <strong>{liveCount}</strong>
                <small>agents affected</small>
              </span>
              <span>
                <strong>&lt; 1 sec</strong>
                <small>propagation target</small>
              </span>
              <span>
                <strong>100%</strong>
                <small>audited</small>
              </span>
            </div>
            <div className="modal-actions">
              <button
                className="button secondary"
                onClick={() => setShowStopConfirm(false)}
                type="button"
              >
                Cancel
              </button>
              <button className="button emergency solid" onClick={stopFleet} type="button">
                Confirm emergency stop
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
