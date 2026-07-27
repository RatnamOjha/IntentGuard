export type ApiDecision = "allow" | "deny" | "review";

export type ApiFinding = {
  code: string;
  message: string;
  blocking: boolean;
};

export type ApiAuthorization = {
  decision: {
    request_id: string;
    decision: ApiDecision;
    findings: ApiFinding[];
    remaining_daily_budget: string;
    policy_version: string;
  };
  reservation: {
    reservation_id: string;
    status: "held" | "committed" | "released" | "expired";
  } | null;
  lease: {
    lease_id: string;
    expires_at: string;
    fleet_epoch: number;
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

export type ActionPayload = {
  request_id: string;
  agent_id: string;
  action: string;
  amount: string;
  currency: string;
  intent_id: string;
  risk_score: number;
  attributes: Record<string, unknown>;
};

const API_BASE_URL =
  process.env.NEXT_PUBLIC_INTENTGUARD_API_URL ?? "http://127.0.0.1:8000";

async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });

  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as
      | { detail?: string }
      | null;
    throw new Error(body?.detail ?? `IntentGuard API returned ${response.status}.`);
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
  return apiRequest<ApiAuthorization>("/v1/actions/authorize", {
    method: "POST",
    body: JSON.stringify(payload),
  });
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
  );
}

export function setAgentRevocation(agentId: string, revoked: boolean) {
  return apiRequest(`/v1/agents/${agentId}/${revoked ? "revoke" : "restore"}`, {
    method: "POST",
  });
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
        operator: "Ratnam Ojha",
        reason: "Policy published from the IntentGuard operator console",
      }),
    },
  );
}

export function setFleetStop(stopped: boolean) {
  return apiRequest(`/v1/fleet/${stopped ? "stop" : "resume"}`, {
    method: "POST",
    body: stopped
      ? JSON.stringify({ reason: "Emergency stop activated by the operator console" })
      : undefined,
  });
}

export function resolveApproval(requestId: string, approved: boolean) {
  return apiRequest<ApiAuthorization | ApiApproval>(
    `/v1/approvals/${requestId}/${approved ? "approve" : "reject"}`,
    {
      method: "POST",
      body: JSON.stringify({
        reviewer: "Ratnam Ojha",
        reason: approved
          ? "Card-member intent and transaction context verified"
          : "Risk could not be resolved by the operator",
      }),
    },
  );
}
