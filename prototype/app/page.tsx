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
import { AgentRoster } from "./components/AgentRoster";
import { DecisionFeed, type FeedRow } from "./components/DecisionFeed";
import { Money } from "./components/Money";
import { Panel } from "./components/Panel";
import { ScenarioList } from "./components/ScenarioList";
import { Verdict, type VerdictData, type VerdictOutcome } from "./components/Verdict";
import { scenarios, type ScenarioKey } from "./lib/scenarios";
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
  const [scenarioKey, setScenarioKey] = useState<ScenarioKey>("overLimit");
  const [verdict, setVerdict] = useState<VerdictData | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [link, setLink] = useState<
    "connecting" | "live" | "offline" | "expired"
  >("connecting");
  const [chat, setChat] = useState<ChatLine[]>([]);
  const [planner, setPlanner] = useState<string | null>(null);
  const [talking, setTalking] = useState(false);

  const pending = approvals.filter((approval) => approval.status === "pending");

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

  async function run() {
    const scenario = scenarios[scenarioKey];
    const payload: ActionPayload = {
      request_id: `req_${scenarioKey}_${Date.now()}`,
      agent_id: scenario.agentId,
      action: scenario.actionCode,
      amount: scenario.amountValue,
      currency: "INR",
      intent_id: scenario.intentId,
      risk_score: scenario.riskScore,
      attributes: { ...scenario.attributes },
    };
    setBusy(true);
    const startedAt = performance.now();
    let restoreFleetAfter = false;
    try {
      if (scenarioKey === "stale" && fleetStopped) await setFleetStop(false);
      const authorization = await authorizeAction(payload);

      // The stale-lease scenario is the only one that needs a second act: hold
      // a valid lease, stop the fleet, then present it to the connector.
      if (scenarioKey === "stale" && authorization.decision.decision === "allow") {
        await setFleetStop(true);
        restoreFleetAfter = true;
        let rejection = "";
        try {
          await commitAuthorization(authorization);
        } catch (error) {
          rejection = error instanceof Error ? error.message : "The connector rejected the lease.";
        }
        if (!rejection) throw new Error("The connector unexpectedly accepted a stale lease.");
        setVerdict({
          outcome: "Blocked",
          agentName: scenario.agent,
          action: scenario.actionCode,
          amount: scenario.amountValue,
          findings: [
            {
              code: "STALE_LEASE_REJECTED",
              message: rejection,
              blocking: true,
              context: null,
            },
          ],
          latencyMs: performance.now() - startedAt,
          remainingBudget: Number(authorization.decision.remaining_daily_budget),
          leaseId: null,
        });
        await setFleetStop(false);
        restoreFleetAfter = false;
        await refresh();
        setNotice("The connector refused a lease that the emergency stop had invalidated.");
        return;
      }

      if (authorization.decision.decision === "allow") await commitAuthorization(authorization);

      setVerdict({
        outcome: outcomeOf(authorization.decision.decision),
        agentName: scenario.agent,
        action: scenario.actionCode,
        amount: scenario.amountValue,
        findings: authorization.decision.findings,
        latencyMs: performance.now() - startedAt,
        remainingBudget: Number(authorization.decision.remaining_daily_budget),
        leaseId: authorization.lease?.lease_id ?? null,
      });
      await refresh();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Evaluation failed.");
    } finally {
      if (restoreFleetAfter) {
        try {
          await setFleetStop(false);
          await refresh();
        } catch {
          setNotice("The lease was blocked, but the fleet still needs restoring.");
        }
      }
      setBusy(false);
    }
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
      const turn = await sendAgentMessage(scenarios[scenarioKey].agentId, message);
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
          agentName: scenarios[scenarioKey].agent,
          action: turn.proposal.action,
          amount: turn.proposal.amount,
          findings: turn.authorization.decision.findings,
          latencyMs: performance.now() - startedAt,
          remainingBudget: Number(
            turn.authorization.decision.remaining_daily_budget,
          ),
          leaseId: turn.authorization.lease?.lease_id ?? null,
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
    const scenario = scenarios[scenarioKey];
    const agent = agents.find((candidate) => candidate.agent_id === scenario.agentId);
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
      </header>

      {notice ? (
        <div className={styles.notice} role="status">
          <span>{notice}</span>
          <button onClick={() => setNotice("")} type="button" aria-label="Dismiss">×</button>
        </div>
      ) : null}

      <main className={styles.main}>
        <section className={styles.intro}>
          <h1 className={styles.h1}>
            Your support agent can issue refunds.
            <br />
            <span>It cannot issue the wrong ones.</span>
          </h1>
          <p className={styles.lede}>
            Three AI agents handle refunds for a subscription company. Each one has
            limits it cannot see, argue with, or change. Pick a request below and
            watch the engine decide — every decision is sealed in a hash-chained
            audit trail.
          </p>
        </section>

        <section className={styles.console}>
          <div className={styles.left}>
            <AgentChat
              busy={talking}
              disabled={busy || link !== "live"}
              lines={chat}
              onSend={(message) => void talk(message)}
              planner={planner}
            />

            <h2 className={`${styles.stepLabel} ${styles.orLabel}`}>
              <span className={styles.step}>or</span> run a prepared request
            </h2>
            <ScenarioList
              disabled={busy || link !== "live"}
              onSelect={(key) => {
                setScenarioKey(key);
                setVerdict(null);
              }}
              selected={scenarioKey}
            />
            <button
              className={styles.run}
              disabled={busy || link !== "live"}
              onClick={() => void run()}
              type="button"
            >
              {busy ? "Evaluating…" : "Run it through IntentGuard"}
              <span aria-hidden="true"> →</span>
            </button>
            <button
              className={styles.reset}
              disabled={busy || talking}
              onClick={() => {
                setChat([]);
                void reset();
              }}
              type="button"
            >
              Reset demo
            </button>
          </div>

          <div className={styles.right}>
            <h2 className={styles.stepLabel}>
              <span className={styles.step}>→</span> The decision
            </h2>
            <Verdict
              busy={busy}
              data={verdict}
              onAmend={(patch, label) => void amend(patch, label)}
            />
          </div>
        </section>

        {pending.length > 0 ? (
          <Panel
            title="Waiting for a human"
            hint="These scored high enough on risk that no lease was issued until a person decides."
          >
            <ul className={styles.approvals}>
              {pending.map((approval) => (
                <li key={approval.request_id}>
                  <div>
                    <strong>{approval.action.replaceAll("_", " ")}</strong>
                    <span className={styles.approvalMeta}>
                      {approval.agent_id} · <Money amount={approval.amount} size="sm" /> · risk{" "}
                      {approval.risk_score}
                    </span>
                  </div>
                  <div className={styles.approvalActions}>
                    <button
                      className={styles.reject}
                      disabled={busy}
                      onClick={() => void decide(approval.request_id, false)}
                      type="button"
                    >
                      Reject
                    </button>
                    <button
                      className={styles.approve}
                      disabled={busy}
                      onClick={() => void decide(approval.request_id, true)}
                      type="button"
                    >
                      Approve
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          </Panel>
        ) : null}

        <Panel
          title="The agents"
          hint="Limits live in policy, not in the prompt. An agent cannot read or change them."
        >
          <AgentRoster agents={agents} busy={busy} onToggle={(id, revoke) => void toggleAgent(id, revoke)} />
        </Panel>

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
      </main>
    </div>
  );
}
