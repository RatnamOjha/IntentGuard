import type { ApiFinding } from "@/lib/intentguard-api";

/**
 * Turns a policy finding into something an operator can act on.
 *
 * Every number here comes from the finding's own `context`, which the engine
 * populates with the values it actually compared. Nothing is reconstructed
 * from a separate agent fetch, so the card cannot drift from the decision it
 * is describing.
 */
export type Explanation = {
  /** One plain sentence naming who did what, and the bound they crossed. */
  headline: string;
  /** The bound, as a number, when the finding compared one. */
  limit: number | null;
  /** The value that crossed it. */
  actual: number | null;
  /** What the same request would have needed to look like to pass. */
  wouldPass: string | null;
  /** Label for the one-click amendment, when this rule is amendable. */
  amend: { label: string; maxActionAmount?: string; addAction?: string } | null;
};

const num = (value: string | number | null | undefined): number | null => {
  if (value === null || value === undefined) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
};

const money = (value: number) =>
  new Intl.NumberFormat("en-IN", {
    style: "currency",
    currency: "INR",
    maximumFractionDigits: 0,
  }).format(value);

const readable = (action: string) => action.replaceAll("_", " ");

export function explain(
  finding: ApiFinding,
  agentName: string,
  action: string,
): Explanation {
  const limit = num(finding.context?.limit);
  const actual = num(finding.context?.actual);
  const permitted = finding.context?.permitted ?? null;

  switch (finding.code) {
    case "AGENT_ACTION_LIMIT":
      return {
        headline:
          limit !== null && actual !== null
            ? `${agentName} asked for ${money(actual)}. Her per-action limit is ${money(limit)}.`
            : `${agentName} asked for more than her per-action limit allows.`,
        limit,
        actual,
        wouldPass: limit !== null ? `Any ${readable(action)} up to ${money(limit)}.` : null,
        amend:
          actual !== null
            ? {
                label: `Raise ${agentName}'s per-action limit to ${money(actual)}`,
                maxActionAmount: String(actual),
              }
            : null,
      };

    case "INTENT_AMOUNT_EXCEEDED":
      return {
        headline:
          limit !== null && actual !== null
            ? `The customer authorised up to ${money(limit)}. This asked for ${money(actual)}.`
            : "The amount is outside what the customer authorised.",
        limit,
        actual,
        wouldPass:
          limit !== null ? `An amount within the customer's ${money(limit)} authorisation.` : null,
        // Deliberately not amendable from here: the ceiling belongs to the
        // customer's signed intent, not to a policy an operator may edit.
        amend: null,
      };

    case "DAILY_BUDGET_EXCEEDED":
      return {
        headline:
          limit !== null && actual !== null
            ? `${money(actual)} requested against ${money(limit)} left in today's budget.`
            : "The action exceeds the remaining daily budget.",
        limit,
        actual,
        wouldPass:
          limit !== null && limit > 0
            ? `Any ${readable(action)} up to ${money(limit)} today.`
            : "Nothing further today — the daily budget is spent.",
        amend: null,
      };

    case "ACTION_NOT_PERMITTED":
      return {
        headline: permitted
          ? `${agentName} may ${[...permitted].sort().map(readable).join(" and ")} — not ${readable(action)}.`
          : `${agentName} is not permitted to ${readable(action)}.`,
        limit: null,
        actual: null,
        wouldPass: permitted
          ? `Any of: ${[...permitted].sort().map(readable).join(", ")}.`
          : null,
        amend: { label: `Let ${agentName} ${readable(action)}`, addAction: action },
      };

    default:
      return {
        headline: finding.message,
        limit,
        actual,
        wouldPass: null,
        amend: null,
      };
  }
}
