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
