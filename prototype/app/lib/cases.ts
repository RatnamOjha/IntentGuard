import type { ApiClaimReason, ApiEvidenceKind } from "@/lib/intentguard-api";

export type CaseEvidence = {
  kind: ApiEvidenceKind;
  reference: string;
  /** Set for bundled demo fixtures. Uploaded evidence is fetched by
   *  reference instead, because the endpoint needs an auth header. */
  previewUrl?: string;
};

export type CaseRecord = {
  id: string;
  orderReference: string;
  customer: string;
  reason: ApiClaimReason;
  orderValue: string;
  daysSinceDelivery: number;
  /** The customer's own words. Untrusted: quote it, never style it as
   *  something the system said. */
  complaint: string;
  evidence: CaseEvidence[];
  filedAt: string;
  /** Which agent picks this up, and the intent it may cite. */
  agentId: string;
  intentId: string;
  /** What the agent proposes. The point of the product is that policy, not
   *  this number, decides what actually happens. */
  proposedAction: string;
  proposedAmount: string;
  riskScore: number;
};

export const REASON_LABEL: Record<ApiClaimReason, string> = {
  defect: "Arrived damaged",
  not_delivered: "Never arrived",
  late: "Arrived late",
  changed_mind: "Changed their mind",
};

export const SEEDED_CASES: CaseRecord[] = [
  {
    id: "case-4418",
    orderReference: "ORD-88213",
    customer: "R. Mehta",
    reason: "defect",
    orderValue: "4200",
    daysSinceDelivery: 2,
    complaint:
      "The dinner set arrived with three plates shattered. The outer box was crushed on one corner. I have attached a photo and the receipt.",
    evidence: [
      { kind: "photo", reference: "img-4418-a", previewUrl: "/demo/damaged-parcel.svg" },
      { kind: "receipt", reference: "rcpt-88213" },
    ],
    filedAt: "09:12",
    agentId: "agt_refund_01",
    intentId: "intent_refund_routine",
    proposedAction: "refund_order",
    proposedAmount: "4200",
    riskScore: 15,
  },
  {
    id: "case-4417",
    orderReference: "ORD-88190",
    customer: "S. Iyer",
    reason: "defect",
    orderValue: "380",
    daysSinceDelivery: 1,
    complaint: "The mug was cracked when it came out of the box.",
    evidence: [
      { kind: "photo", reference: "img-4417-a", previewUrl: "/demo/damaged-parcel.svg" },
    ],
    filedAt: "09:31",
    agentId: "agt_refund_01",
    intentId: "intent_refund_routine",
    proposedAction: "refund_order",
    proposedAmount: "380",
    riskScore: 8,
  },
  {
    id: "case-4421",
    orderReference: "ORD-88301",
    customer: "A. Bose",
    reason: "not_delivered",
    orderValue: "1200",
    daysSinceDelivery: 11,
    complaint:
      "Tracking says delivered but nothing arrived. I was home all day and no one rang.",
    evidence: [{ kind: "courier_scan", reference: "scan-77120" }],
    filedAt: "10:04",
    agentId: "agt_refund_02",
    intentId: "intent_refund_escalated",
    proposedAction: "refund_order",
    proposedAmount: "1200",
    riskScore: 22,
  },
  {
    id: "case-4420",
    orderReference: "ORD-88355",
    customer: "K. Nair",
    reason: "changed_mind",
    orderValue: "4800",
    daysSinceDelivery: 3,
    complaint: "I ordered the wrong size and would like to return it.",
    evidence: [],
    filedAt: "10:22",
    agentId: "agt_refund_02",
    intentId: "intent_goodwill_credit",
    proposedAction: "issue_goodwill_credit",
    proposedAmount: "4800",
    riskScore: 88,
  },
];
