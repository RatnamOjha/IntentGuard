"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import {
  type ActionPayload,
  type ApiAgent,
  type ApiApproval,
  type ApiAuditEvent,
  type ApiAuditStatus,
  type ApiAuthorization,
  authorizeAction,
  bootstrapDemo,
  commitAuthorization,
  getAgents,
  getApprovals,
  getAuditEvents,
  getAuditStatus,
  getFleetStatus,
  resetDemo,
  resolveApproval,
  setAgentRevocation,
  setFleetStop,
} from "@/lib/intentguard-api";

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

const scenarios = {
  booking: {
    title: "Compliant travel booking",
    agent: "Atlas",
    agentId: "agt_travel_01",
    action: "Book hotel · BOM",
    actionCode: "book_hotel",
    amount: "₹12,400",
    amountValue: "12400",
    intentId: "intent_travel_booking",
    riskScore: 22,
    attributes: { city: "BOM", refundable: true },
  },
  cap: {
    title: "Dynamic spend cap breach",
    agent: "Nova",
    agentId: "agt_service_02",
    action: "Issue service credit",
    amount: "₹18,500",
    amountValue: "18500",
    actionCode: "issue_service_credit",
    intentId: "intent_service_credit",
    riskScore: 30,
    attributes: {},
  },
  permission: {
    title: "Out-of-scope merchant payment",
    agent: "Orbit",
    agentId: "agt_benefits_03",
    action: "Pay external merchant",
    amount: "₹31,200",
    amountValue: "31200",
    actionCode: "pay_external_merchant",
    intentId: "intent_external_payment",
    riskScore: 35,
    attributes: {},
  },
  approval: {
    title: "High-risk fee reversal",
    agent: "Nova",
    agentId: "agt_service_02",
    action: "Reverse annual fee",
    amount: "₹4,500",
    amountValue: "4500",
    actionCode: "reverse_annual_fee",
    intentId: "intent_fee_reversal",
    riskScore: 85,
    attributes: {},
  },
};

type ScenarioKey = keyof typeof scenarios;

type Result = {
  requestId: string;
  decision: Decision;
  reason: string;
  latency: string;
  findings: string[];
  remainingBudget: number;
  leaseId: string | null;
};

const agentPresentation: Record<string, { role: string; initials: string }> = {
  agt_travel_01: { role: "Travel concierge", initials: "AT" },
  agt_service_02: { role: "Service recovery", initials: "NV" },
  agt_benefits_03: { role: "Benefits assistant", initials: "OR" },
};

function formatCurrency(amount: unknown, currency = "INR") {
  const value = Number(amount);
  if (!Number.isFinite(value)) return "—";
  return new Intl.NumberFormat("en-IN", {
    style: "currency",
    currency,
    maximumFractionDigits: 0,
  }).format(value);
}

function readableAction(action: unknown) {
  if (typeof action !== "string") return "Governance control";
  return action
    .replaceAll("_", " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function toAgent(agent: ApiAgent): Agent {
  const presentation = agentPresentation[agent.agent_id] ?? {
    role: "Financial agent",
    initials: agent.name.slice(0, 2).toUpperCase(),
  };
  return {
    id: agent.agent_id,
    name: agent.name,
    role: presentation.role,
    initials: presentation.initials,
    status: agent.revoked || !agent.active ? "Revoked" : "Live",
    spent: Number(agent.spent_today) + Number(agent.reserved_today),
    budget: Number(agent.daily_budget),
    permissions: agent.allowed_actions.length,
  };
}

function decisionLabel(value: unknown): Decision {
  if (value === "allow") return "Allowed";
  if (value === "review") return "Review";
  return "Blocked";
}

function toEvent(event: ApiAuditEvent, agentNames: Record<string, string>): Event | null {
  const payload = event.payload;
  const agentId = typeof payload.agent_id === "string" ? payload.agent_id : "";
  const base = {
    id: `evt_${event.sequence}`,
    time: new Date(event.occurred_at).toLocaleTimeString("en-GB", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }),
    agent: agentNames[agentId] ?? (agentId || "Entire fleet"),
    amount: formatCurrency(payload.amount, String(payload.currency ?? "INR")),
    latency:
      typeof payload.latency_ms === "number"
        ? `${payload.latency_ms.toFixed(2)} ms`
        : "—",
  };

  if (event.event_type === "gateway.authorization.completed") {
    const findings = Array.isArray(payload.finding_codes)
      ? payload.finding_codes.join(", ")
      : "Policy evaluated";
    return {
      ...base,
      action: readableAction(payload.action),
      decision: decisionLabel(payload.decision),
      reason: findings,
    };
  }
  if (event.event_type === "action.executed") {
    return {
      ...base,
      action: "Historical protected action",
      decision: "Allowed",
      reason: "Execution recorded against the live daily budget",
    };
  }
  if (event.event_type === "approval.requested") {
    return {
      ...base,
      action: readableAction(payload.action),
      decision: "Review",
      reason: `Risk score ${String(payload.risk_score)}`,
    };
  }
  if (event.event_type === "approval.approved") {
    return {
      ...base,
      action: "Human approval granted",
      decision: "Allowed",
      reason: String(payload.reason ?? "Operator approved"),
    };
  }
  if (event.event_type === "approval.rejected") {
    return {
      ...base,
      action: "Human approval rejected",
      decision: "Blocked",
      reason: String(payload.reason ?? "Operator rejected"),
    };
  }
  if (event.event_type === "agent.revoked" || event.event_type === "agent.restored") {
    const restored = event.event_type === "agent.restored";
    return {
      ...base,
      action: restored ? "Agent restored" : "Execution revoked",
      decision: restored ? "Allowed" : "Blocked",
      reason: "Manual operator control",
    };
  }
  if (event.event_type === "fleet.stopped" || event.event_type === "fleet.resumed") {
    const resumed = event.event_type === "fleet.resumed";
    return {
      ...base,
      action: resumed ? "Fleet restored" : "Emergency stop",
      decision: resumed ? "Allowed" : "Blocked",
      reason: String(payload.reason ?? "Operator fleet control"),
    };
  }
  return null;
}

export default function Home() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [approvals, setApprovals] = useState<ApiApproval[]>([]);
  const [auditStatus, setAuditStatus] = useState<ApiAuditStatus>({
    verified: false,
    event_count: 0,
    head_hash: "",
  });
  const [scenarioKey, setScenarioKey] = useState<ScenarioKey>("booking");
  const [lastResult, setLastResult] = useState<Result | null>(null);
  const [fleetStopped, setFleetStopped] = useState(false);
  const [showStopConfirm, setShowStopConfirm] = useState(false);
  const [notice, setNotice] = useState("");
  const [activeNav, setActiveNav] = useState("Overview");
  const [connectionState, setConnectionState] = useState<
    "connecting" | "live" | "offline"
  >("connecting");
  const [isWorking, setIsWorking] = useState(false);

  const liveCount = agents.filter((agent) => agent.status === "Live").length;
  const pendingApprovals = approvals.filter(
    (approval) => approval.status === "pending",
  );
  const summary = useMemo(
    () => ({
      allowed: events.filter((event) => event.decision === "Allowed").length,
      blocked: events.filter((event) => event.decision === "Blocked").length,
      review: pendingApprovals.length,
    }),
    [events, pendingApprovals.length],
  );
  const p95Latency = useMemo(() => {
    const samples = events
      .map((event) => Number.parseFloat(event.latency))
      .filter(Number.isFinite)
      .sort((a, b) => a - b);
    if (!samples.length) return "—";
    return samples[Math.ceil(samples.length * 0.95) - 1].toFixed(2);
  }, [events]);

  const refreshData = useCallback(async () => {
    const [apiAgents, fleet, apiApprovals, auditEvents, status] = await Promise.all([
      getAgents(),
      getFleetStatus(),
      getApprovals(),
      getAuditEvents(),
      getAuditStatus(),
    ]);
    const mappedAgents = apiAgents.map(toAgent);
    const names = Object.fromEntries(
      mappedAgents.map((agent) => [agent.id, agent.name]),
    );
    setAgents(mappedAgents);
    setFleetStopped(fleet.stopped);
    setApprovals(apiApprovals);
    setAuditStatus(status);
    setEvents(
      auditEvents
        .map((event) => toEvent(event, names))
        .filter((event): event is Event => event !== null)
        .reverse(),
    );
    setConnectionState("live");
  }, []);

  useEffect(() => {
    void (async () => {
      try {
        await bootstrapDemo();
        await refreshData();
      } catch (error) {
        setConnectionState("offline");
        setNotice(
          error instanceof Error
            ? `Backend unavailable: ${error.message}`
            : "Backend unavailable. Start the FastAPI service and retry.",
        );
      }
    })();
  }, [refreshData]);

  async function simulate() {
    const selected = scenarios[scenarioKey];
    const payload: ActionPayload = {
      request_id: `req_${scenarioKey}_${Date.now()}`,
      agent_id: selected.agentId,
      action: selected.actionCode,
      amount: selected.amountValue,
      currency: "INR",
      intent_id: selected.intentId,
      risk_score: selected.riskScore,
      attributes: selected.attributes,
    };
    setIsWorking(true);
    const startedAt = performance.now();
    try {
      const authorization = await authorizeAction(payload);
      if (authorization.decision.decision === "allow") {
        await commitAuthorization(authorization);
      }
      const elapsed = performance.now() - startedAt;
      const decision = decisionLabel(authorization.decision.decision);
      const findings = authorization.decision.findings.map(
        (finding) => finding.code,
      );
      const primaryFinding =
        authorization.decision.findings.find((finding) => finding.blocking) ??
        authorization.decision.findings.at(-1);
      setLastResult({
        requestId: authorization.decision.request_id,
        decision,
        reason: primaryFinding?.message ?? "Runtime policy evaluated.",
        latency: `${elapsed.toFixed(2)} ms`,
        findings,
        remainingBudget: Number(
          authorization.decision.remaining_daily_budget,
        ),
        leaseId: authorization.lease?.lease_id ?? null,
      });
      setNotice(
        decision === "Review"
          ? "High-risk action routed to the live approval queue."
          : `Decision ${decision.toLowerCase()}, execution lifecycle completed, and audit evidence sealed.`,
      );
      await refreshData();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Evaluation failed.");
    } finally {
      setIsWorking(false);
    }
  }

  async function toggleAgent(agentId: string) {
    const target = agents.find((agent) => agent.id === agentId);
    if (!target) return;
    setIsWorking(true);
    try {
      const revoke = target.status === "Live";
      await setAgentRevocation(agentId, revoke);
      await refreshData();
      setNotice(`${target.name} ${revoke ? "revoked" : "restored"} successfully.`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Agent control failed.");
    } finally {
      setIsWorking(false);
    }
  }

  async function stopFleet() {
    setShowStopConfirm(false);
    setIsWorking(true);
    try {
      await setFleetStop(true);
      await refreshData();
      setNotice("Emergency stop propagated to all agents and leases invalidated.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Fleet stop failed.");
    } finally {
      setIsWorking(false);
    }
  }

  async function restoreFleet() {
    setIsWorking(true);
    try {
      await setFleetStop(false);
      await refreshData();
      setNotice("Fleet restored. New actions will receive fresh execution leases.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Fleet restore failed.");
    } finally {
      setIsWorking(false);
    }
  }

  async function decideApproval(requestId: string, approved: boolean) {
    setIsWorking(true);
    try {
      const result = await resolveApproval(requestId, approved);
      if (approved && "decision" in result) {
        const authorization = result as ApiAuthorization;
        await commitAuthorization(authorization);
        setLastResult({
          requestId,
          decision: "Allowed",
          reason: "Operator approval granted and protected action executed.",
          latency: "human verified",
          findings: authorization.decision.findings.map(
            (finding) => finding.code,
          ),
          remainingBudget: Number(
            authorization.decision.remaining_daily_budget,
          ),
          leaseId: authorization.lease?.lease_id ?? null,
        });
      }
      await refreshData();
      setNotice(
        approved
          ? "Approval granted, bounded lease issued, and budget committed."
          : "Approval rejected and final denial added to the audit chain.",
      );
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Approval failed.");
    } finally {
      setIsWorking(false);
    }
  }

  async function resetSandbox() {
    setIsWorking(true);
    try {
      await resetDemo();
      setLastResult(null);
      await refreshData();
      setNotice("Demo data reset to the initial verified state.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Demo reset failed.");
    } finally {
      setIsWorking(false);
    }
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
                  if (item === "Approvals") {
                    document
                      .getElementById("approvals")
                      ?.scrollIntoView({ behavior: "smooth" });
                  }
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
                if (item === "Audit trail") {
                  document
                    .getElementById("audit-trail")
                    ?.scrollIntoView({ behavior: "smooth" });
                }
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
            <span
              className={auditStatus.verified ? "integrity-icon" : "integrity-icon pending"}
              aria-hidden="true"
            >
              {auditStatus.verified ? "✓" : "…"}
            </span>
            <div>
              <strong>
                {auditStatus.verified ? "Audit chain verified" : "Awaiting backend"}
              </strong>
              <small>{auditStatus.event_count} events sealed</small>
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
            <div
              className={
                fleetStopped || connectionState === "offline"
                  ? "system-state danger"
                  : "system-state"
              }
            >
              <span className="pulse" />
              <span>
                <small>
                  {connectionState === "live" ? "LIVE API · FLEET STATUS" : "API STATUS"}
                </small>
                <strong>
                  {connectionState === "offline"
                    ? "Backend offline"
                    : connectionState === "connecting"
                      ? "Connecting"
                      : fleetStopped
                        ? "Emergency stop"
                        : "Operational"}
                </strong>
              </span>
            </div>
            {fleetStopped ? (
              <button
                className="button primary"
                disabled={isWorking}
                onClick={restoreFleet}
                type="button"
              >
                Restore fleet
              </button>
            ) : (
              <button
                className="button emergency"
                disabled={isWorking || connectionState !== "live"}
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
              <strong>{p95Latency}</strong>
              <small>milliseconds</small>
            </div>
            <div className="latency-copy">
              <strong>Measured gateway latency</strong>
              <small>Derived from live API decisions</small>
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
              <span className="metric-note positive">Backend decisions executed</span>
            </div>
          </article>
          <article className="metric-card">
            <span className="metric-icon red">×</span>
            <div>
              <p>Blocked today</p>
              <strong>{summary.blocked}</strong>
              <span className="metric-note">Policy or operator prevented</span>
            </div>
          </article>
          <article className="metric-card">
            <span className="metric-icon amber">!</span>
            <div>
              <p>Awaiting review</p>
              <strong>{summary.review}</strong>
              <span className="metric-note warning">Live operator queue</span>
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
              <div className="panel-header-actions">
                <button
                  className="text-button"
                  disabled={isWorking}
                  onClick={resetSandbox}
                  type="button"
                >
                  Reset demo
                </button>
                <span
                  className={
                    connectionState === "live"
                      ? "sandbox-badge"
                      : "sandbox-badge disconnected"
                  }
                >
                  {connectionState === "live" ? "Live backend" : "Connecting"}
                </span>
              </div>
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

            <button
              className="evaluate-button"
              disabled={isWorking || connectionState !== "live"}
              onClick={simulate}
              type="button"
            >
              {isWorking ? "Evaluating…" : "Evaluate through FastAPI"}{" "}
              <span aria-hidden="true">→</span>
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
                  <div className="result-evidence">
                    {lastResult.findings.slice(0, 3).map((finding) => (
                      <span key={finding}>{finding}</span>
                    ))}
                  </div>
                  <small className="result-proof">
                    Remaining budget {formatCurrency(lastResult.remainingBudget)}
                    {lastResult.leaseId
                      ? ` · Lease ${lastResult.leaseId.slice(0, 14)}…`
                      : ""}
                  </small>
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
                          disabled={isWorking}
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

        <section className="panel approvals-panel" id="approvals">
          <div className="panel-header">
            <div>
              <span className="panel-kicker">HUMAN-IN-THE-LOOP CONTROL</span>
              <h3>Approval queue</h3>
            </div>
            <span className={pendingApprovals.length ? "queue-count active" : "queue-count"}>
              {pendingApprovals.length} pending
            </span>
          </div>
          {pendingApprovals.length ? (
            <div className="approval-list">
              {pendingApprovals.map((approval) => {
                const agent =
                  agents.find((item) => item.id === approval.agent_id)?.name ??
                  approval.agent_id;
                return (
                  <article className="approval-row" key={approval.request_id}>
                    <div className="approval-risk">
                      <span>RISK</span>
                      <strong>{approval.risk_score}</strong>
                    </div>
                    <div className="approval-copy">
                      <span className="approval-agent">{agent}</span>
                      <strong>{readableAction(approval.action)}</strong>
                      <small>
                        {formatCurrency(approval.amount, approval.currency)} ·{" "}
                        {approval.request_id}
                      </small>
                    </div>
                    <div className="approval-reason">
                      <span>WHY REVIEW</span>
                      <strong>Risk threshold exceeded</strong>
                      <small>Operator confirmation required before lease issuance.</small>
                    </div>
                    <div className="approval-actions">
                      <button
                        className="button secondary compact"
                        disabled={isWorking}
                        onClick={() => decideApproval(approval.request_id, false)}
                        type="button"
                      >
                        Reject
                      </button>
                      <button
                        className="button primary compact"
                        disabled={isWorking}
                        onClick={() => decideApproval(approval.request_id, true)}
                        type="button"
                      >
                        Approve & execute
                      </button>
                    </div>
                  </article>
                );
              })}
            </div>
          ) : (
            <div className="approval-empty">
              <span aria-hidden="true">✓</span>
              <div>
                <strong>No actions awaiting review</strong>
                <p>
                  Run the high-risk fee reversal scenario to create a live approval.
                </p>
              </div>
            </div>
          )}
        </section>

        <section className="panel events-panel" id="audit-trail">
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
              <i aria-hidden="true">{auditStatus.verified ? "✓" : "!"}</i>{" "}
              {auditStatus.verified ? "SHA-256 chain verified" : "Audit verification pending"}{" "}
              through event {auditStatus.event_count}
            </span>
            <button
              className="text-button"
              onClick={() =>
                setNotice(
                  `Evidence head ${auditStatus.head_hash.slice(0, 16)}… is ready for export.`,
                )
              }
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
              <button
                className="button emergency solid"
                disabled={isWorking}
                onClick={stopFleet}
                type="button"
              >
                {isWorking ? "Stopping…" : "Confirm emergency stop"}
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
