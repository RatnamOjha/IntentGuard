/**
 * The requests an operator can put through the engine.
 *
 * Each one states plainly what it is asking for and what should happen, so a
 * first-time viewer can predict the outcome before pressing Run. `expect` is
 * narration only -- the decision always comes from the engine.
 */
export const scenarios = {
  overLimit: {
    title: "A refund above the agent's limit",
    blurb: "Ada handles tier-one refunds up to ₹500. This ticket asks for ₹4,200.",
    expect: "Refused",
    agent: "Ada",
    agentId: "agt_refund_01",
    action: "Refund order",
    actionCode: "refund_order",
    amount: "₹4,200",
    amountValue: "4200",
    intentId: "intent_refund_routine",
    riskScore: 15,
    attributes: { ticket: "SUP-4418" },
    claim: {
      reason: "defect",
      order_value: "4200",
      days_since_delivery: 2,
      order_reference: "ORD-88213",
      artifacts: [
        { kind: "photo", reference: "img-4418-a" },
        { kind: "receipt", reference: "rcpt-88213" },
      ],
      complaint:
        "The dinner set arrived with three plates shattered. The outer box was crushed on one corner. I have attached a photo and the receipt.",
    },
  },
  routine: {
    title: "A refund inside policy",
    blurb: "The same agent, a ₹380 refund on a damaged item. Well inside her limit.",
    expect: "Allowed",
    agent: "Ada",
    agentId: "agt_refund_01",
    action: "Refund order",
    actionCode: "refund_order",
    amount: "₹380",
    amountValue: "380",
    intentId: "intent_refund_routine",
    riskScore: 8,
    attributes: { ticket: "SUP-4417" },
    claim: {
      reason: "defect",
      order_value: "380",
      days_since_delivery: 1,
      order_reference: "ORD-88190",
      artifacts: [{ kind: "photo", reference: "img-4417-a" }],
      complaint: "The mug was cracked when it came out of the box.",
    },
  },
  notPermitted: {
    title: "The billing agent tries to refund",
    blurb: "Cy adjusts billing. Refunds are not in the set of actions Cy may take.",
    expect: "Refused",
    agent: "Cy",
    agentId: "agt_billing_03",
    action: "Refund order",
    actionCode: "refund_order",
    amount: "₹750",
    amountValue: "750",
    intentId: "intent_billing_change",
    riskScore: 20,
    attributes: { ticket: "SUP-4419", reason: "billing_dispute" },
  },
  review: {
    title: "A large goodwill credit",
    blurb: "Bo may escalate to ₹5,000, but ₹4,800 scores high enough to need a person.",
    expect: "Human review",
    agent: "Bo",
    agentId: "agt_refund_02",
    action: "Goodwill credit",
    actionCode: "issue_goodwill_credit",
    amount: "₹4,800",
    amountValue: "4800",
    intentId: "intent_goodwill_credit",
    riskScore: 88,
    attributes: { ticket: "SUP-4420", reason: "service_outage" },
  },
  stale: {
    title: "A refund after the emergency stop",
    blurb: "A lease issued before the fleet was halted, presented after. The connector rejects it.",
    expect: "Refused",
    agent: "Bo",
    agentId: "agt_refund_02",
    action: "Refund order",
    actionCode: "refund_order",
    amount: "₹1,200",
    amountValue: "1200",
    intentId: "intent_refund_escalated",
    riskScore: 10,
    attributes: { ticket: "SUP-4421" },
    claim: {
      reason: "not_delivered",
      order_value: "1200",
      days_since_delivery: 11,
      order_reference: "ORD-88301",
      artifacts: [{ kind: "courier_scan", reference: "scan-77120" }],
      complaint: "Tracking says delivered but nothing arrived. I was home all day.",
    },
  },
} as const;

export type ScenarioKey = keyof typeof scenarios;
