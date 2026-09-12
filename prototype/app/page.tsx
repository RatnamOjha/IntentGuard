"use client";

import { useCallback, useEffect, useState } from "react";

import {
  type ActionPayload,
  type ApiAgent,
  type ApiApproval,
  type ApiAuditEvent,
  type ApiAuditStatus,
  type ApiAuthorization,
  ApiError,
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
  sendAgentMessage,
  setAgentRevocation,
  setFleetStop,
  updateAgentPolicy,
} from "@/lib/intentguard-api";

import { AgentChat, type ChatLine } from "./components/AgentChat";
import { ComplaintForm } from "./components/ComplaintForm";
import { EvidenceViewer } from "./components/EvidenceViewer";
import {
  REASON_LABEL,
  SEEDED_CASES,
  type CaseRecord,
} from "./lib/cases";
import { AgentRoster } from "./components/AgentRoster";
import { DecisionFeed, type FeedRow } from "./components/DecisionFeed";
import { Panel } from "./components/Panel";
import { Verdict, type VerdictData, type VerdictOutcome } from "./components/Verdict";
import styles from "./page.module.css";

function outcomeOf(decision: string): VerdictOutcome {
  if (decision === "allow") return "Allowed";
  if (decision === "review") return "Review";
  return "Blocked";
}

function money(value: unknown, currency = "INR") {
  const amount = Number(value);
  if (!Number.isFinite(amount)) return "—";
  return new Intl.NumberFormat("en-IN", {
    style: "currency",
    currency,
    maximumFractionDigits: 0,
  }).format(amount);
}

function toFeedRow(event: ApiAuditEvent, names: Record<string, string>): FeedRow | null {
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
    agent: names[agentId] ?? (agentId || "Fleet"),
    amount: payload.amount === undefined ? "" : money(payload.amount, String(payload.currency ?? "INR")),
  };
  const action = (value: unknown) =>
    typeof value === "string" ? value.replaceAll("_", " ") : "Governance control";

  switch (event.event_type) {
    case "gateway.authorization.completed":
      return {
        ...base,
        action: action(payload.action),
        decision: outcomeOf(String(payload.decision)),
        reason: Array.isArray(payload.finding_codes)
          ? payload.finding_codes.join(" · ")
          : "evaluated",
      };
    case "approval.requested":
      return {
        ...base,
        action: action(payload.action),
        decision: "Review",
        reason: `risk ${String(payload.risk_score)}`,
      };
    case "approval.approved":
      return { ...base, action: "Human approval", decision: "Allowed", reason: "operator approved" };
    case "approval.rejected":
      return { ...base, action: "Human approval", decision: "Blocked", reason: "operator rejected" };
    case "agent.revoked":
      return { ...base, action: "Agent revoked", decision: "Blocked", reason: "operator control" };
    case "agent.restored":
      return { ...base, action: "Agent restored", decision: "Allowed", reason: "operator control" };
    case "fleet.stopped":
      return { ...base, action: "Emergency stop", decision: "Blocked", reason: "fleet halted" };
    case "fleet.resumed":
      return { ...base, action: "Fleet resumed", decision: "Allowed", reason: "fleet running" };
    case "connector.execution.rejected":
      return { ...base, action: "Connector rejected lease", decision: "Blocked", reason: "lease invalid" };
    case "connector.execution.succeeded":
      return { ...base, action: "Connector executed", decision: "Allowed", reason: "lease valid" };
    case "policy.updated":
      return {
        ...base,
        action: "Policy published",
        decision: "Allowed",
        reason: String(payload.policy_version ?? "updated"),
      };
    default:
      return null;
  }
}

export default function Console() {
  const [agents, setAgents] = useState<ApiAgent[]>([]);
  const [approvals, setApprovals] = useState<ApiApproval[]>([]);
  const [feed, setFeed] = useState<FeedRow[]>([]);
  const [audit, setAudit] = useState<ApiAuditStatus | null>(null);
  // Which evaluator decided. The built-in engine and Rego are deliberately
  // not equivalent, so a chain that verifies does not by itself say what was
  // enforced. Read from the record rather than inferred.
  const [evaluator, setEvaluator] = useState<string | null>(null);
  const [fleetStopped, setFleetStopped] = useState(false);
  const [verdict, setVerdict] = useState<VerdictData | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [link, setLink] = useState<
    "connecting" | "live" | "offline" | "expired"
  >("connecting");
  const [chat, setChat] = useState<ChatLine[]>([]);
  const [planner, setPlanner] = useState<string | null>(null);
  const [talking, setTalking] = useState(false);
  const [mode, setMode] = useState<"desk" | "file">("desk");
  const [cases, setCases] = useState<CaseRecord[]>(SEEDED_CASES);
  const [openCaseId, setOpenCaseId] = useState<string>(SEEDED_CASES[0].id);
  // One verdict per case, so moving between cases does not lose the decision
  // that was already taken on each.
  const [verdicts, setVerdicts] = useState<Record<string, VerdictData>>({});

  const pending = approvals.filter((approval) => approval.status === "pending");
  const openCase = cases.find((record) => record.id === openCaseId) ?? null;

  const refresh = useCallback(async () => {
    const [nextAgents, fleet, nextApprovals, events, status] = await Promise.all([
      getAgents(),
      getFleetStatus(),
      getApprovals(),
      getAuditEvents(),
      getAuditStatus(),
    ]);
    const names = Object.fromEntries(nextAgents.map((a) => [a.agent_id, a.name]));
    setAgents(nextAgents);
    setFleetStopped(fleet.stopped);
    setApprovals(nextApprovals);
    setAudit(status);
    setFeed(
      events
        .map((event) => toFeedRow(event, names))
        .filter((row): row is FeedRow => row !== null)
        .reverse(),
    );
    const decided = [...events]
      .reverse()
      .find((event) => event.event_type === "policy.evaluated");
    setEvaluator(
      typeof decided?.payload.policy_engine === "string"
        ? decided.payload.policy_engine
        : null,
    );
    setLink("live");
  }, []);

  useEffect(() => {
    void (async () => {
      try {
        await bootstrapDemo();
        await refresh();
      } catch (error) {
        // A 401 means the demo's startup tokens aged out, not that the API
        // died. Reporting both as "offline" sent us looking at the wrong
        // process more than once.
        const expired = error instanceof ApiError && error.status === 401;
        setLink(expired ? "expired" : "offline");
        setNotice(
          expired
            ? "The demo's access tokens have expired. Restart ./scripts/start-demo.sh to mint fresh ones."
            : error instanceof Error
              ? `Backend unavailable: ${error.message}`
              : "Backend unavailable.",
        );
      }
    })();
  }, [refresh]);

  /** Put one case through the engine.
   *
   *  The agent proposes what it thinks the complaint is worth; the claim
   *  travels with it, and policy decides which remedy may actually be
   *  honoured and up to how much. */
  async function runCase(record: CaseRecord) {
    const payload: ActionPayload = {
      request_id: `req_${record.id}_${Date.now()}`,
      agent_id: record.agentId,
      action: record.proposedAction,
      amount: record.proposedAmount,
      currency: "INR",
      intent_id: record.intentId,
      risk_score: record.riskScore,
      attributes: { ticket: record.orderReference },
      claim: {
        reason: record.reason,
        order_value: record.orderValue,
        days_since_delivery: record.daysSinceDelivery,
        order_reference: record.orderReference,
        artifacts: record.evidence.map(({ kind, reference }) => ({
          kind,
          reference,
        })),
        complaint: record.complaint,
      },
    };
    setBusy(true);
    const startedAt = performance.now();
    try {
      const authorization = await authorizeAction(payload);
      if (authorization.decision.decision === "allow") {
        await commitAuthorization(authorization);
      }
      setVerdicts((current) => ({
        ...current,
        [record.id]: {
          outcome: outcomeOf(authorization.decision.decision),
          agentName: agentNameFor(record.agentId),
          action: record.proposedAction,
          amount: record.proposedAmount,
          findings: authorization.decision.findings,
          latencyMs: performance.now() - startedAt,
          remainingBudget: Number(authorization.decision.remaining_daily_budget),
          leaseId: authorization.lease?.lease_id ?? null,
          remedy: authorization.decision.remedy,
        },
      }));
      await refresh();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Evaluation failed.");
    } finally {
      setBusy(false);
    }
  }

  function agentNameFor(agentId: string): string {
    return agents.find((agent) => agent.agent_id === agentId)?.name ?? agentId;
  }

  /** One conversational turn. The agent proposes; the engine decides, and its
   *  decision lands in the same verdict card the scenarios use. */
  async function talk(message: string) {
    const stamp = Date.now();
    setChat((current) => [
      ...current,
      { id: `c${stamp}`, from: "customer", text: message },
    ]);
    setTalking(true);
    const startedAt = performance.now();
    try {
      const turn = await sendAgentMessage("agt_refund_01", message);
      setPlanner(turn.planner);
      setChat((current) => [
        ...current,
        {
          id: `a${stamp}`,
          from: "agent",
          text: turn.reply,
          decision: turn.decision,
        },
      ]);
      // Only a proposal that reached the engine has a decision to show.
      if (turn.authorization && turn.proposal) {
        setVerdict({
          outcome: outcomeOf(turn.authorization.decision.decision),
          agentName: agentNameFor("agt_refund_01"),
          action: turn.proposal.action,
          amount: turn.proposal.amount,
          findings: turn.authorization.decision.findings,
          latencyMs: performance.now() - startedAt,
          remainingBudget: Number(
            turn.authorization.decision.remaining_daily_budget,
          ),
          leaseId: turn.authorization.lease?.lease_id ?? null,
          remedy: turn.authorization.decision.remedy,
        });
      }
      await refresh();
    } catch (error) {
      setChat((current) => [
        ...current,
        {
          id: `e${stamp}`,
          from: "agent",
          text:
            error instanceof Error
              ? error.message
              : "The agent could not be reached.",
        },
      ]);
    } finally {
      setTalking(false);
    }
  }

  /** The one-click path off a refusal: widen the rule that fired, then re-run. */
  async function amend(
    patch: { maxActionAmount?: string; addAction?: string },
    label: string,
  ) {
    // Amend the agent that was actually refused: the one on the open case in
    // the desk, or the tier-one agent the chat talks to.
    const agentId = mode === "desk" && openCase ? openCase.agentId : "agt_refund_01";
    const agent = agents.find((candidate) => candidate.agent_id === agentId);
    if (!agent) return;
    setBusy(true);
    try {
      await updateAgentPolicy(agent.agent_id, {
        allowed_actions: patch.addAction
          ? [...new Set([...agent.allowed_actions, patch.addAction])]
          : agent.allowed_actions,
        max_action_amount: patch.maxActionAmount ?? agent.max_action_amount,
        daily_budget: agent.daily_budget,
        active: agent.active,
      });
      await refresh();
      setNotice(`${label}. Run it again to see the new decision.`);
      setVerdict(null);
      if (openCase) {
        setVerdicts((current) => {
          const next = { ...current };
          delete next[openCase.id];
          return next;
        });
      }
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Policy change failed.");
    } finally {
      setBusy(false);
    }
  }

  async function toggleAgent(agentId: string, revoke: boolean) {
    setBusy(true);
    try {
      await setAgentRevocation(agentId, revoke);
      await refresh();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Agent control failed.");
    } finally {
      setBusy(false);
    }
  }

  async function decide(requestId: string, approved: boolean) {
    setBusy(true);
    try {
      const result = await resolveApproval(requestId, approved);
      if (approved && "decision" in result) {
        await commitAuthorization(result as ApiAuthorization);
      }
      await refresh();
      setNotice(approved ? "Approved, and a bounded lease was issued." : "Rejected.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Approval failed.");
    } finally {
      setBusy(false);
    }
  }

  async function reset() {
    setBusy(true);
    try {
      await resetDemo();
      setVerdict(null);
      await refresh();
      setNotice("Demo reset.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Reset failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={styles.page}>
      <header className={styles.bar}>
        <div className={styles.brand}>
          <span className={styles.mark} aria-hidden="true">IG</span>
          <div>
            <strong>IntentGuard</strong>
            <span className={styles.tagline}>
              Authorization for AI agents that spend money
            </span>
          </div>
        </div>
        <div className={styles.barRight}>
          <span
            className={
              link !== "live"
                ? `${styles.status} ${styles.statusOff}`
                : fleetStopped
                  ? `${styles.status} ${styles.statusStop}`
                  : styles.status
            }
          >
            <span className={styles.statusDot} aria-hidden="true" />
            {link === "offline"
              ? "Backend offline"
              : link === "expired"
                ? "Tokens expired"
                : link === "connecting"
                  ? "Connecting"
                  : fleetStopped
                    ? "Fleet stopped"
                    : "Fleet running"}
          </span>
          <button
            className={fleetStopped ? styles.resume : styles.stop}
            disabled={busy || link !== "live"}
            onClick={() => void (async () => {
              setBusy(true);
              try {
                await setFleetStop(!fleetStopped);
                await refresh();
              } finally {
                setBusy(false);
              }
            })()}
            type="button"
          >
            {fleetStopped ? "Resume fleet" : "Emergency stop"}
          </button>
        </div>
        <div className={styles.modes} role="tablist" aria-label="View">
          <button
            aria-selected={mode === "desk"}
            className={mode === "desk" ? styles.modeOn : styles.mode}
            onClick={() => setMode("desk")}
            role="tab"
            type="button"
          >
            Refund desk
          </button>
          <button
            aria-selected={mode === "file"}
            className={mode === "file" ? styles.modeOn : styles.mode}
            onClick={() => setMode("file")}
            role="tab"
            type="button"
          >
            File a complaint
          </button>
        </div>
        <button
          className={styles.resetTop}
          disabled={busy || talking}
          onClick={() => {
            setChat([]);
            setVerdicts({});
            setCases(SEEDED_CASES);
            setOpenCaseId(SEEDED_CASES[0].id);
            void reset();
          }}
          type="button"
        >
          Reset demo
        </button>
      </header>

      {notice ? (
        <div className={styles.notice} role="status">
          <span>{notice}</span>
          <button onClick={() => setNotice("")} type="button" aria-label="Dismiss">×</button>
        </div>
      ) : null}
      {mode === "file" ? (
        <main className={styles.lane}>
          <AgentChat
            busy={talking}
            disabled={link !== "live"}
            lines={chat}
            onSend={(message) => void talk(message)}
            planner={planner}
          />
          {verdict || talking ? (
            <Verdict
              busy={talking}
              data={verdict}
              onAmend={(patch, label) => void amend(patch, label)}
            />
          ) : null}
          <ComplaintForm
            busy={busy}
            onFiled={(record) => {
              setCases((current) => [record, ...current]);
              setOpenCaseId(record.id);
              setMode("desk");
              setNotice(
                "Filed. It is now in the queue with the evidence attached.",
              );
            }}
          />
        </main>
      ) : (
        <main className={styles.desk}>
          <aside className={styles.queue}>
            <h2 className={styles.railHead}>
              Queue <span>{cases.length}</span>
            </h2>
            <ul className={styles.caseList}>
              {cases.map((record) => {
                const settled = verdicts[record.id];
                return (
                  <li key={record.id}>
                    <button
                      className={
                        record.id === openCaseId
                          ? `${styles.caseRow} ${styles.caseRowOpen}`
                          : styles.caseRow
                      }
                      onClick={() => setOpenCaseId(record.id)}
                      type="button"
                    >
                      <span className={styles.caseTop}>
                        <span className={styles.caseOrder}>
                          {record.orderReference}
                        </span>
                        <span className={styles.caseTime}>{record.filedAt}</span>
                      </span>
                      <span className={styles.caseWho}>{record.customer}</span>
                      <span className={styles.caseReason}>
                        {REASON_LABEL[record.reason]} · ₹{record.orderValue}
                      </span>
                      <span className={styles.caseFoot}>
                        <span className={styles.caseEvidence}>
                          {record.evidence.length === 0
                            ? "no evidence"
                            : `${record.evidence.length} attached`}
                        </span>
                        {settled ? (
                          <span
                            className={
                              settled.outcome === "Allowed"
                                ? `${styles.caseTag} ${styles.tagOk}`
                                : settled.outcome === "Review"
                                  ? `${styles.caseTag} ${styles.tagHold}`
                                  : `${styles.caseTag} ${styles.tagStop}`
                            }
                          >
                            {settled.outcome === "Blocked"
                              ? "Refused"
                              : settled.outcome === "Review"
                                ? "Review"
                                : "Allowed"}
                          </span>
                        ) : (
                          <span className={styles.caseTag}>open</span>
                        )}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </aside>

          {openCase ? (
            <section className={styles.caseView}>
              <header className={styles.caseHead}>
                <div>
                  <h2 className={styles.caseTitle}>
                    {REASON_LABEL[openCase.reason]}
                  </h2>
                  <p className={styles.caseSub}>
                    {openCase.customer} · {openCase.orderReference} · filed{" "}
                    {openCase.filedAt}
                  </p>
                </div>
                <dl className={styles.caseFacts}>
                  <div>
                    <dt>Order value</dt>
                    <dd>₹{openCase.orderValue}</dd>
                  </div>
                  <div>
                    <dt>Since delivery</dt>
                    <dd>
                      {openCase.daysSinceDelivery} day
                      {openCase.daysSinceDelivery === 1 ? "" : "s"}
                    </dd>
                  </div>
                </dl>
              </header>

              <h3 className={styles.sectionLabel}>Evidence filed</h3>
              <EvidenceViewer
                evidence={openCase.evidence}
                orderReference={openCase.orderReference}
                orderValue={openCase.orderValue}
              />

              <h3 className={styles.sectionLabel}>
                Customer&rsquo;s words <span>unverified</span>
              </h3>
              {/* Rendered as text, never markup. This string reaches the agent
                  too, so it is already an injection surface; it must never be
                  styled to look like something the system said. */}
              <blockquote className={styles.quote}>
                {openCase.complaint}
              </blockquote>
            </section>
          ) : null}

          <aside className={styles.decision}>
            <h2 className={styles.railHead}>Decision</h2>
            {openCase ? (
              <div className={styles.proposal}>
                <span className={styles.proposalLabel}>The agent proposes</span>
                <p className={styles.proposalLine}>
                  <strong>₹{openCase.proposedAmount}</strong>{" "}
                  {openCase.proposedAction.replace(/_/g, " ")}
                </p>
                <p className={styles.proposalWho}>
                  {agentNameFor(openCase.agentId)} · risk {openCase.riskScore}
                </p>
              </div>
            ) : null}

            <button
              className={styles.runCase}
              disabled={busy || !openCase || link !== "live"}
              onClick={() => openCase && void runCase(openCase)}
              type="button"
            >
              {busy ? "Evaluating…" : "Put it through IntentGuard"}
              <span aria-hidden="true"> →</span>
            </button>

            <Verdict
              busy={busy}
              data={openCase ? (verdicts[openCase.id] ?? null) : null}
              onAmend={(patch, label) => void amend(patch, label)}
            />
          </aside>
        </main>
      )}

      <section className={styles.below}>
        <Panel
          title="The agents"
          hint="Limits live in policy, not in the prompt. An agent cannot read or change them."
        >
          <AgentRoster
            agents={agents}
            busy={busy}
            onToggle={(id, revoke) => void toggleAgent(id, revoke)}
          />
        </Panel>

        {pending.length > 0 ? (
          <Panel
            title="Waiting for a human"
            hint="These scored high enough on risk that no lease was issued until a person decides."
          >
            <ul className={styles.approvals}>
              {pending.map((approval) => (
                <li key={approval.request_id}>
                  <span>
                    {approval.action.replace(/_/g, " ")} · ₹{approval.amount}
                  </span>
                  <span className={styles.approvalActions}>
                    <button
                      disabled={busy}
                      onClick={() => void decide(approval.request_id, true)}
                      type="button"
                    >
                      Approve
                    </button>
                    <button
                      disabled={busy}
                      onClick={() => void decide(approval.request_id, false)}
                      type="button"
                    >
                      Reject
                    </button>
                  </span>
                </li>
              ))}
            </ul>
          </Panel>
        ) : null}

        <Panel
          title="Every decision, in order"
          hint="Append-only and hash-chained. Editing or deleting any entry breaks verification."
          action={
            audit ? (
              <span className={audit.verified ? styles.chainOk : styles.chainBad}>
                {audit.verified ? "Chain verified" : "Chain broken"} · {audit.event_count} events
                {evaluator
                  ? ` · decided by ${evaluator === "opa_rego" ? "Rego" : "built-in"}`
                  : ""}
              </span>
            ) : null
          }
        >
          <DecisionFeed rows={feed} />
        </Panel>
      </section>
    </div>
  );
}
