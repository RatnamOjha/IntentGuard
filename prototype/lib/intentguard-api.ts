export type ApiDecision = "allow" | "deny" | "review";

/** The values the engine itself compared. Absent for boolean checks. */
export type ApiFindingContext = {
  /** The ceiling policy set, in the request's currency. */
  limit: string | number | null;
  /** The value that breached `limit`. Engine-side, never echoed request text. */
  actual: string | number | null;
  /** Actions this agent's policy permits. Unordered -- sort before display. */
  permitted: string[] | null;
};

export type ApiFinding = {
  code: string;
  message: string;
  blocking: boolean;
  context: ApiFindingContext | null;
};

export type ApiRiskAssessment = {
  /** Self-reported by the agent. Untrusted: it can only raise the effective score. */
  declared: number;
  /** Computed by the gateway from state the agent cannot forge. */
  derived: number;
  signals: string[];
};

export type ApiAuthorization = {
  decision: {
    request_id: string;
    decision: ApiDecision;
    findings: ApiFinding[];
    remaining_daily_budget: string;
    policy_version: string;
    risk: ApiRiskAssessment | null;
    remedy: ApiRemedy | null;
  };
  reservation: {
    reservation_id: string;
    status: "held" | "committed" | "released" | "expired";
  } | null;
  lease: {
    lease_id: string;
    expires_at: string;
    fleet_epoch: number;
    action: string;
    amount: string;
    currency: string;
    issuer: string;
    audience: string;
    key_id: string;
    token: string;
  } | null;
};

export type ApiAgent = {
  agent_id: string;
  name: string;
  active: boolean;
  revoked: boolean;
  allowed_actions: string[];
  max_action_amount: string;
  daily_budget: string;
  spent_today: string;
  reserved_today: string;
  remaining_budget: string;
};

export type ApiApproval = {
  request_id: string;
  agent_id: string;
  action: string;
  amount: string;
  currency: string;
  risk_score: number;
  created_at: string;
  status: "pending" | "approved" | "rejected";
  reviewer: string | null;
  reason: string | null;
  resolved_at: string | null;
};

export type ApiAuditEvent = {
  sequence: number;
  occurred_at: string;
  event_type: string;
  payload: Record<string, unknown>;
  previous_hash: string;
  event_hash: string;
};

export type ApiAuditStatus = {
  verified: boolean;
  event_count: number;
  head_hash: string;
  /** Tracked outside the chain, so truncation of the newest events is visible. */
  expected_event_count: number;
  expected_head_hash: string;
  /** 1-based position of the first broken link, or null when the chain is intact. */
  first_invalid_link: number | null;
};

export type ApiBenchmark = {
  iterations: number;
  acceptance: {
    total: number;
    passed: number;
    failed: number;
    category_count: number;
    categories: string[];
    failures: Array<Record<string, unknown>>;
    results: Array<Record<string, unknown>>;
  };
  engine_latency_ms: {
    scope: "in_process_policy_engine";
    p50: number;
    p95: number;
    p99: number;
  };
  concurrency: {
    requests: number;
    allowed: number;
    budget: string;
    reserved_total: string;
    overspend_violations: number;
  };
  audit_chain_verified: boolean;
};

export type ApiRoundTripBenchmark = {
  scope: "browser_to_fastapi_authorization";
  iterations: number;
  p50: number;
  p95: number;
  p99: number;
};

export type ApiPolicyVersion = {
  version_id: string;
  source: string;
  status: "draft" | "published" | "retired";
  created_at: string;
  created_by: string;
  description: string;
  based_on: string | null;
};

/** One turn of the governed conversation. The agent proposes; it never decides. */
export type ApiAgentTurn = {
  reply: string;
  /** Which planner produced the proposal: "scripted", or "<provider>:<model>". */
  planner: string;
  decision: ApiDecision | null;
  blocked_reasons: string[];
  proposal: {
    intent_id: string;
    action: string;
    amount: string;
    currency: string;
    rationale: string;
    risk_score: number;
  } | null;
  authorization: ApiAuthorization | null;
};

export type ApiEvidenceKind = "photo" | "receipt" | "courier_scan";

/** A citation into the merchant's systems, never bytes the gateway serves. */
export type ApiEvidenceArtifact = {
  kind: ApiEvidenceKind;
  reference: string;
};

export type ApiClaimReason =
  | "defect"
  | "not_delivered"
  | "late"
  | "changed_mind";

export type ApiClaim = {
  reason: ApiClaimReason;
  order_value: string;
  days_since_delivery: number;
  order_reference: string | null;
  artifacts: ApiEvidenceArtifact[];
  /** The customer's own words. Untrusted: render as a quotation, never as
   *  chrome, and never with dangerouslySetInnerHTML. */
  complaint: string | null;
};

/** What policy will honour -- an envelope, not an instruction. */
export type ApiRemedy = {
  kind: "refund_to_source" | "store_credit" | "shipping_refund" | "reschedule" | "none";
  cap: string | number;
};

export type ActionPayload = {
  request_id: string;
  agent_id: string;
  action: string;
  amount: string;
  currency: string;
  intent_id: string;
  risk_score: number;
  attributes: Record<string, unknown>;
  claim?: {
    reason: ApiClaimReason;
    order_value: string;
    days_since_delivery: number;
    order_reference?: string;
    artifacts?: ApiEvidenceArtifact[];
    complaint?: string;
  };
};

/** The seeded demo customer. The gateway takes the real one from the token
 *  and rejects a mismatch, so this is a convenience, not an identity claim. */
export const DEMO_CUSTOMER_ID = "demo-customer";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_INTENTGUARD_API_URL ?? "http://127.0.0.1:8000";
const ACCESS_TOKEN = process.env.NEXT_PUBLIC_INTENTGUARD_ACCESS_TOKEN;
const AGENT_ACCESS_TOKEN =
  process.env.NEXT_PUBLIC_INTENTGUARD_AGENT_ACCESS_TOKEN ?? ACCESS_TOKEN;
const OPERATOR_ACCESS_TOKEN =
  process.env.NEXT_PUBLIC_INTENTGUARD_OPERATOR_ACCESS_TOKEN ?? ACCESS_TOKEN;
const REVIEWER_ACCESS_TOKEN =
  process.env.NEXT_PUBLIC_INTENTGUARD_REVIEWER_ACCESS_TOKEN ?? ACCESS_TOKEN;
const CUSTOMER_ACCESS_TOKEN =
  process.env.NEXT_PUBLIC_INTENTGUARD_CUSTOMER_ACCESS_TOKEN ?? ACCESS_TOKEN;

/**
 * A bearer token names the single agent it may act for, so driving several
 * agents needs one token each. Keyed by agent id; falls back to the single
 * agent token when the map is absent.
 */
const AGENT_TOKENS: Record<string, string> = (() => {
  const raw = process.env.NEXT_PUBLIC_INTENTGUARD_AGENT_TOKENS;
  if (!raw) return {};
  try {
    return JSON.parse(raw) as Record<string, string>;
  } catch {
    return {};
  }
})();

function tokenForAgent(agentId: string) {
  return AGENT_TOKENS[agentId] ?? AGENT_ACCESS_TOKEN;
}

/** An API error that keeps its HTTP status, so 401 can be told from a
 *  network failure. Both used to surface as "Backend offline". */
export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function apiRequest<T>(
  path: string,
  init?: RequestInit,
  accessToken = ACCESS_TOKEN,
): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      ...init?.headers,
    },
  });

  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as
      | { detail?: string }
      | null;
    throw new ApiError(
      body?.detail ?? `IntentGuard API returned ${response.status}.`,
      response.status,
    );
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export function bootstrapDemo() {
  return apiRequest("/v1/demo/bootstrap", { method: "POST" });
}

export function resetDemo() {
  return apiRequest("/v1/demo/reset", { method: "POST" });
}

export function getAgents() {
  return apiRequest<ApiAgent[]>("/v1/agents");
}

export function getFleetStatus() {
  return apiRequest<{ stopped: boolean; fleet_epoch: number }>("/v1/fleet/status");
}

export function getApprovals() {
  return apiRequest<ApiApproval[]>("/v1/approvals");
}

export function getAuditEvents() {
  return apiRequest<ApiAuditEvent[]>("/v1/audit/events");
}

export function getAuditStatus() {
  return apiRequest<ApiAuditStatus>("/v1/audit/status");
}

export function getBenchmark() {
  return apiRequest<ApiBenchmark>("/v1/demo/benchmark");
}

function percentile(values: number[], percentileValue: number) {
  const ordered = [...values].sort((left, right) => left - right);
  const index = Math.max(
    0,
    Math.min(
      ordered.length - 1,
      Math.round((ordered.length - 1) * percentileValue),
    ),
  );
  return ordered[index];
}

export async function runApiRoundTripBenchmark(
  iterations = 25,
): Promise<ApiRoundTripBenchmark> {
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new Error("API benchmark iterations must be a positive integer.");
  }

  const runId = `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  const probe = (index: number, phase: string) =>
    apiRequest<{ decision: ApiDecision; server_processing_ms: number }>(
      "/v1/demo/benchmark/authorize-probe",
      {
        method: "POST",
        body: JSON.stringify({
          request_id: `probe-${runId}-${phase}-${index}`,
        }),
      },
    );

  for (let index = 0; index < 3; index += 1) {
    await probe(index, "warmup");
  }

  const samples: number[] = [];
  for (let index = 0; index < iterations; index += 1) {
    const startedAt = performance.now();
    const response = await probe(index, "measured");
    if (response.decision !== "allow") {
      throw new Error("The API authorization probe did not receive an allow decision.");
    }
    samples.push(performance.now() - startedAt);
  }

  return {
    scope: "browser_to_fastapi_authorization",
    iterations,
    p50: Number(percentile(samples, 0.5).toFixed(3)),
    p95: Number(percentile(samples, 0.95).toFixed(3)),
    p99: Number(percentile(samples, 0.99).toFixed(3)),
  };
}

export function authorizeAction(payload: ActionPayload) {
  return apiRequest<ApiAuthorization>(
    "/v1/actions/authorize",
    {
      method: "POST",
      body: JSON.stringify(payload),
    },
    tokenForAgent(payload.agent_id),
  );
}

export function commitAuthorization(authorization: ApiAuthorization) {
  if (!authorization.reservation || !authorization.lease) {
    throw new Error("The authorization did not include an execution lease.");
  }
  return apiRequest(
    `/v1/reservations/${authorization.reservation.reservation_id}/commit`,
    {
      method: "POST",
      body: JSON.stringify({ lease_id: authorization.lease.lease_id }),
    },
    AGENT_ACCESS_TOKEN,
  );
}

export function setAgentRevocation(agentId: string, revoked: boolean) {
  return apiRequest(
    `/v1/agents/${agentId}/${revoked ? "revoke" : "restore"}`,
    { method: "POST" },
    OPERATOR_ACCESS_TOKEN,
  );
}

export function updateAgentPolicy(
  agentId: string,
  policy: {
    allowed_actions: string[];
    max_action_amount: string;
    daily_budget: string;
    active: boolean;
  },
) {
  return apiRequest<{ agent: ApiAgent; policy_version: string }>(
    `/v1/agents/${agentId}/policy`,
    {
      method: "PUT",
      body: JSON.stringify({
        ...policy,
        reason: "Policy published from the IntentGuard operator console",
      }),
    },
    OPERATOR_ACCESS_TOKEN,
  );
}

export function setFleetStop(stopped: boolean) {
  return apiRequest(
    `/v1/fleet/${stopped ? "stop" : "resume"}`,
    {
      method: "POST",
      body: stopped
        ? JSON.stringify({ reason: "Emergency stop activated by the operator console" })
        : undefined,
    },
    OPERATOR_ACCESS_TOKEN,
  );
}

export function resolveApproval(requestId: string, approved: boolean) {
  return apiRequest<ApiAuthorization | ApiApproval>(
    `/v1/approvals/${requestId}/${approved ? "approve" : "reject"}`,
    {
      method: "POST",
      body: JSON.stringify({
        reason: approved
          ? "Card-member intent and transaction context verified"
          : "Risk could not be resolved by the operator",
      }),
    },
    REVIEWER_ACCESS_TOKEN,
  );
}

/** Send one customer message to the governed agent. */
export function sendAgentMessage(agentId: string, message: string) {
  return apiRequest<ApiAgentTurn>(
    "/v1/agent/message",
    {
      method: "POST",
      body: JSON.stringify({
        customer_id: DEMO_CUSTOMER_ID,
        agent_id: agentId,
        message,
      }),
    },
    CUSTOMER_ACCESS_TOKEN,
  );
}

export function getPolicyVersions() {
  return apiRequest<ApiPolicyVersion[]>("/v1/policies", undefined, OPERATOR_ACCESS_TOKEN);
}
