"use client";

import type { ApiFinding } from "@/lib/intentguard-api";
import { explain } from "../lib/explain";
import { Breach } from "./Breach";
import { Money } from "./Money";
import { ReasonCode } from "./ReasonCode";
import styles from "./Verdict.module.css";

export type VerdictOutcome = "Allowed" | "Blocked" | "Review";

export type VerdictData = {
  outcome: VerdictOutcome;
  agentName: string;
  action: string;
  amount: string;
  findings: ApiFinding[];
  latencyMs: number;
  remainingBudget: number;
  leaseId: string | null;
};

const HEADING: Record<VerdictOutcome, string> = {
  Allowed: "Allowed",
  Blocked: "Refused",
  Review: "Sent for human review",
};

const SUBHEAD: Record<VerdictOutcome, string> = {
  Allowed: "A single-use execution lease was issued and the budget committed.",
  Blocked: "The request never reached the payment system.",
  Review: "It is waiting in the approval queue. No lease was issued.",
};

export function Verdict({
  data,
  onAmend,
  busy,
}: {
  data: VerdictData | null;
  onAmend: (patch: { maxActionAmount?: string; addAction?: string }, label: string) => void;
  busy: boolean;
}) {
  if (!data) {
    return (
      <div className={styles.empty}>
        <p className={styles.emptyTitle}>The decision appears here.</p>
        <p className={styles.emptyBody}>
          Pick a request on the left and run it. If IntentGuard refuses, you will
          see the exact rule that fired and the number that broke it.
        </p>
      </div>
    );
  }

  const tone =
    data.outcome === "Allowed" ? "pass" : data.outcome === "Review" ? "hold" : "stop";

  // The blocking finding is the one that decided the outcome; a non-blocking
  // tail exists on allows, where the last finding is the satisfied policy.
  const primary =
    data.findings.find((finding) => finding.blocking) ?? data.findings.at(-1) ?? null;
  const reading = primary ? explain(primary, data.agentName, data.action) : null;
  const others = data.findings.filter((finding) => finding !== primary);
  const codeTone = data.outcome === "Review" ? "hold" : "stop";
  // The default explanation falls back to the finding's own message; showing
  // it as both headline and rule text reads as a stutter.
  const headlineRepeatsRule = reading?.headline === primary?.message;

  return (
    <article className={`${styles.card} ${styles[tone]}`} key={data.latencyMs}>
      <header className={styles.head}>
        <div className={styles.verdictLine}>
          <span className={styles.dot} aria-hidden="true" />
          <h2 className={styles.verdict}>{HEADING[data.outcome]}</h2>
        </div>
        <span className={styles.latency}>
          <span className="tabular">{data.latencyMs.toFixed(0)}</span> ms
        </span>
      </header>

      <p className={styles.subhead}>{SUBHEAD[data.outcome]}</p>

      {reading && !headlineRepeatsRule ? (
        <p className={styles.headline}>{reading.headline}</p>
      ) : null}

      {primary && data.outcome !== "Allowed" ? (
        <section className={styles.rule}>
          <div className={styles.ruleHead}>
            <span className={styles.ruleLabel}>The rule that fired</span>
            <ReasonCode code={primary.code} tone={codeTone} />
          </div>
          <p className={headlineRepeatsRule ? styles.ruleLead : styles.ruleMessage}>
            {primary.message}
          </p>

          {reading && reading.limit !== null && reading.actual !== null ? (
            <Breach limit={reading.limit} actual={reading.actual} />
          ) : null}

          {reading?.wouldPass ? (
            <p className={styles.wouldPass}>
              <span>Would have passed</span> {reading.wouldPass}
            </p>
          ) : null}

          {reading?.amend ? (
            <button
              className={styles.amend}
              disabled={busy}
              onClick={() =>
                onAmend(
                  {
                    maxActionAmount: reading.amend?.maxActionAmount,
                    addAction: reading.amend?.addAction,
                  },
                  reading.amend?.label ?? "Policy amended",
                )
              }
              type="button"
            >
              {reading.amend.label}
              <span aria-hidden="true"> →</span>
            </button>
          ) : null}
        </section>
      ) : null}

      {others.length > 0 ? (
        <div className={styles.also}>
          <span className={styles.alsoLabel}>Also found</span>
          {others.map((finding) => (
            <ReasonCode
              key={finding.code}
              code={finding.code}
              tone={finding.blocking ? codeTone : "soft"}
            />
          ))}
        </div>
      ) : null}

      <footer className={styles.foot}>
        <span>
          Budget left <Money amount={data.remainingBudget} size="sm" tone="faint" />
        </span>
        {data.leaseId ? (
          <span className={styles.lease}>Lease {data.leaseId.slice(0, 16)}…</span>
        ) : (
          <span className={styles.lease}>No lease issued</span>
        )}
        <span className={styles.sealed}>Sealed in the audit chain</span>
      </footer>
    </article>
  );
}
