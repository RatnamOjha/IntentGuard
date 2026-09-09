"use client";

import type { ApiAgent } from "@/lib/intentguard-api";
import { Money } from "./Money";
import styles from "./AgentRoster.module.css";

const ROLE: Record<string, string> = {
  agt_refund_01: "Tier-one refunds",
  agt_refund_02: "Refund escalations",
  agt_billing_03: "Billing adjustments",
};

/** Least to most authority, which is the order the story introduces them in. */
const ORDER = ["agt_refund_01", "agt_refund_02", "agt_billing_03"];
const rank = (id: string) => {
  const index = ORDER.indexOf(id);
  return index === -1 ? ORDER.length : index;
};

export function AgentRoster({
  agents,
  busy,
  onToggle,
}: {
  agents: ApiAgent[];
  busy: boolean;
  onToggle: (agentId: string, revoke: boolean) => void;
}) {
  return (
    <div className={styles.list}>
      {[...agents]
        .sort((a, b) => rank(a.agent_id) - rank(b.agent_id))
        .map((agent) => {
        const spent = Number(agent.spent_today) + Number(agent.reserved_today);
        const budget = Number(agent.daily_budget);
        const used = budget > 0 ? Math.min((spent / budget) * 100, 100) : 0;
        const state = agent.revoked ? "revoked" : agent.active ? "live" : "inactive";
        return (
          <article className={styles.agent} key={agent.agent_id}>
            <div className={styles.head}>
              <div>
                <h3 className={styles.name}>{agent.name}</h3>
                <p className={styles.role}>{ROLE[agent.agent_id] ?? "Financial agent"}</p>
              </div>
              <span className={`${styles.state} ${styles[state]}`}>
                {state === "live" ? "Active" : state === "revoked" ? "Revoked" : "Inactive"}
              </span>
            </div>

            <dl className={styles.limits}>
              <div>
                <dt>Per action</dt>
                <dd><Money amount={agent.max_action_amount} size="sm" /></dd>
              </div>
              <div>
                <dt>Today</dt>
                <dd>
                  <Money amount={spent} size="sm" tone="faint" />
                  <span className={styles.of}> of </span>
                  <Money amount={budget} size="sm" />
                </dd>
              </div>
            </dl>

            <div className={styles.track} aria-hidden="true">
              <span
                className={used > 85 ? `${styles.bar} ${styles.hot}` : styles.bar}
                style={{ width: `${used}%` }}
              />
            </div>

            <div className={styles.foot}>
              <span className={styles.actions}>
                {agent.allowed_actions.map((a) => a.replaceAll("_", " ")).sort().join(" · ")}
              </span>
              <button
                className={styles.control}
                disabled={busy}
                onClick={() => onToggle(agent.agent_id, !agent.revoked)}
                type="button"
              >
                {agent.revoked ? "Restore" : "Revoke"}
              </button>
            </div>
          </article>
        );
      })}
    </div>
  );
}
