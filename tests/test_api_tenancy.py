"""How a request acquires an organisation, and how an API key authenticates.

Two credential kinds reach the same handlers and must produce the same shape of
principal. What separates them is where the organisation comes from: a key
carries its own, while a token's is looked up in our own membership table
rather than read from a claim (ADR 004).

Nothing here asserts isolation *between* organisations. Repositories are not
scoped yet -- this is the identity half only, and claiming more would be
claiming a capability the code does not have.
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

try:
    from fastapi.testclient import TestClient
except ImportError:
    TestClient = None

from intentguard import AgentProfile, IntentPassport, PolicyEngine  # noqa: E402
from intentguard.auth import JwksAuthenticator  # noqa: E402
from intentguard.tenancy import (  # noqa: E402
    DEFAULT_ORG_ID,
    InMemoryTenancyStore,
    looks_like_api_key,
)
from tests.jwt_test_support import (  # noqa: E402
    AUDIENCE,
    ISSUER,
    JWKS,
    bearer,
    token,
)


def authenticator() -> JwksAuthenticator:
    return JwksAuthenticator(
        issuer=ISSUER, audience=AUDIENCE, jwks=JWKS, minimum_rsa_bits=512
    )


def seeded_engine() -> PolicyEngine:
    engine = PolicyEngine()
    engine.register_agent(
        AgentProfile(
            agent_id="support-01",
            name="Support Agent",
            allowed_actions=frozenset({"refund_order"}),
            max_action_amount=Decimal("20000"),
            daily_budget=Decimal("30000"),
        )
    )
    engine.register_intent(
        IntentPassport(
            intent_id="intent-01",
            customer_id="customer-01",
            agent_id="support-01",
            action="refund_order",
            max_amount=Decimal("18000"),
            currency="INR",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            required_attributes={},
        )
    )
    return engine


def action(request_id: str = "request-01") -> dict:
    return {
        "request_id": request_id,
        "agent_id": "support-01",
        "customer_id": "customer-01",
        "action": "refund_order",
        "amount": "1500",
        "currency": "INR",
        "intent_id": "intent-01",
        "risk_score": 10,
        "attributes": {},
    }


class CredentialKindTest(unittest.TestCase):
    """A key and a JWT must be separable without trying to decode either."""

    def test_a_jwt_is_never_mistaken_for_a_key(self) -> None:
        # Not a style preference: a JWT's first segment is base64url of a JSON
        # object, and `{` encodes such that the segment always starts with "e".
        for roles in (["operator"], ["agent"], ["customer", "admin"]):
            issued = token(subject="user-01", roles=roles)
            self.assertTrue(issued.startswith("e"), issued[:4])
            self.assertFalse(looks_like_api_key(issued))

    def test_an_issued_key_is_recognised_as_one(self) -> None:
        store = InMemoryTenancyStore()
        organization = store.create_organization("Acme", "acme")
        issued = store.issue_key(
            organization.org_id, name="agent", roles=frozenset({"agent"})
        )

        self.assertTrue(looks_like_api_key(issued.secret))


@unittest.skipIf(TestClient is None, "Install the api and dev extras to test FastAPI")
class UntenantedGatewayTest(unittest.TestCase):
    """With no store configured there is one tenant, and it is named."""

    def setUp(self) -> None:
        from intentguard.api import create_app

        self.client = TestClient(
            create_app(seeded_engine(), authenticator=authenticator())
        )

    def test_a_token_subject_acts_for_the_default_organisation(self) -> None:
        response = self.client.post(
            "/v1/actions/authorize",
            json=action(),
            headers=bearer(
                subject="agent-user",
                roles=["agent"],
                agent_id="support-01",
                customer_id="customer-01",
            ),
        )

        self.assertEqual(200, response.status_code, response.text)

    def test_a_key_is_refused_rather_than_read_as_a_malformed_token(self) -> None:
        """The caller is told the truth: keys are not configured here."""

        response = self.client.get(
            "/v1/agents",
            headers={"Authorization": "Bearer ig_live_abcdefghijklmnop"},
        )

        self.assertEqual(401, response.status_code)
        self.assertIn("not configured", response.json()["detail"])


@unittest.skipIf(TestClient is None, "Install the api and dev extras to test FastAPI")
class TenantedGatewayTest(unittest.TestCase):
    def setUp(self) -> None:
        from intentguard.api import create_app

        self.store = InMemoryTenancyStore()
        self.acme = self.store.create_organization("Acme", "acme")
        self.client = TestClient(
            create_app(
                seeded_engine(), authenticator=authenticator(), tenancy=self.store
            )
        )

    def issue(self, **changes: object):
        defaults: dict = {
            "name": "agent key",
            "roles": frozenset({"agent"}),
            "agent_id": "support-01",
            "customer_id": "customer-01",
        }
        defaults.update(changes)
        return self.store.issue_key(self.acme.org_id, **defaults)

    def test_an_api_key_authorizes_an_action(self) -> None:
        issued = self.issue()

        response = self.client.post(
            "/v1/actions/authorize",
            json=action(),
            headers={"Authorization": f"Bearer {issued.secret}"},
        )

        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual("allow", response.json()["decision"]["decision"])

    def test_a_revoked_key_stops_working(self) -> None:
        issued = self.issue()
        self.assertTrue(self.store.revoke_key(self.acme.org_id, issued.record.key_id))

        response = self.client.post(
            "/v1/actions/authorize",
            json=action("request-02"),
            headers={"Authorization": f"Bearer {issued.secret}"},
        )

        self.assertEqual(401, response.status_code)
        self.assertIn("revoked or expired", response.json()["detail"])

    def test_an_expired_key_stops_working(self) -> None:
        issued = self.issue(
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)
        )

        response = self.client.post(
            "/v1/actions/authorize",
            json=action("request-03"),
            headers={"Authorization": f"Bearer {issued.secret}"},
        )

        self.assertEqual(401, response.status_code)

    def test_an_unknown_key_is_refused(self) -> None:
        response = self.client.get(
            "/v1/agents",
            headers={"Authorization": "Bearer ig_live_notarealkeyatall1234"},
        )

        self.assertEqual(401, response.status_code)
        self.assertIn("not recognised", response.json()["detail"])

    def test_an_agent_key_cannot_stop_the_fleet(self) -> None:
        """The roles on the key are the whole of its authority."""

        issued = self.issue()

        response = self.client.post(
            "/v1/fleet/stop",
            json={"reason": "testing"},
            headers={"Authorization": f"Bearer {issued.secret}"},
        )

        self.assertEqual(403, response.status_code)

    def test_an_agent_key_cannot_act_as_another_agent(self) -> None:
        """A key is bound to the identity it was issued for."""

        issued = self.issue(agent_id="someone-else")

        response = self.client.post(
            "/v1/actions/authorize",
            json=action("request-04"),
            headers={"Authorization": f"Bearer {issued.secret}"},
        )

        self.assertEqual(403, response.status_code)

    def test_a_subject_with_no_membership_is_refused(self) -> None:
        """Fail closed. Defaulting a stranger into an organisation is how a
        cross-tenant read gets shipped the day repositories start scoping."""

        response = self.client.get(
            "/v1/agents",
            headers=bearer(subject="stranger", roles=["operator"]),
        )

        self.assertEqual(403, response.status_code)
        self.assertIn("no organisation", response.json()["detail"])

    def test_membership_roles_beat_token_roles(self) -> None:
        """Keycloak says who the caller is; our database says what they may do."""

        self.store.add_member(self.acme.org_id, "demoted", frozenset({"reviewer"}))

        stop = self.client.post(
            "/v1/fleet/stop",
            json={"reason": "testing"},
            headers=bearer(subject="demoted", roles=["operator", "admin"]),
        )
        read = self.client.get(
            "/v1/approvals",
            headers=bearer(subject="demoted", roles=[]),
        )

        self.assertEqual(403, stop.status_code)
        self.assertEqual(200, read.status_code, read.text)

    def test_a_member_acts_for_their_own_organisation(self) -> None:
        self.store.add_member(self.acme.org_id, "operator-1", frozenset({"operator"}))

        response = self.client.get(
            "/v1/agents",
            headers=bearer(subject="operator-1", roles=["operator"]),
        )

        self.assertEqual(200, response.status_code, response.text)
        self.assertNotEqual(DEFAULT_ORG_ID, self.acme.org_id)


@unittest.skipIf(TestClient is None, "Install the api and dev extras to test FastAPI")
class TenancyFollowsTheEngineTest(unittest.TestCase):
    """Where tenancy comes from, pinned.

    ADR 004 enforces tenancy at the repository boundary, and the repositories
    belong to the engine. A caller who builds the engine has taken over the
    construction the gateway would otherwise scope, so it must bring the store
    too. A deployment builds neither and gets both from the environment.

    This is pinned rather than commented because the failure it prevents is
    silent: a production gateway that quietly forgot its organisations would
    answer every request out of the default one.
    """

    def test_a_deployment_gets_tenancy_from_the_database_url(self) -> None:
        from intentguard.api import create_app

        with patch.dict(
            os.environ,
            {"INTENTGUARD_DATABASE_URL": "postgresql://unavailable/tenancy"},
            clear=False,
        ), patch("intentguard.api.configured_engine", return_value=seeded_engine()):
            app = create_app(authenticator=authenticator())

        self.assertTrue(app.state.tenancy_configured)
        # Built lazily: an unreachable database must not stop the gateway
        # starting, because /health/ready is how that is reported.
        self.assertIsNone(app.state.tenancy)

    def test_an_injected_engine_must_bring_its_own_store(self) -> None:
        from intentguard.api import create_app

        with patch.dict(
            os.environ,
            {"INTENTGUARD_DATABASE_URL": "postgresql://unavailable/tenancy"},
            clear=False,
        ):
            app = create_app(seeded_engine(), authenticator=authenticator())

        self.assertFalse(app.state.tenancy_configured)

    def test_an_injected_store_is_used_whatever_the_environment_says(self) -> None:
        from intentguard.api import create_app

        store = InMemoryTenancyStore()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("INTENTGUARD_DATABASE_URL", None)
            app = create_app(
                seeded_engine(), authenticator=authenticator(), tenancy=store
            )

        self.assertTrue(app.state.tenancy_configured)
        self.assertIs(store, app.state.tenancy)

    def test_an_unreachable_store_is_a_503_not_a_downgrade(self) -> None:
        """Fail closed. The alternative is serving one tenant out of another."""

        from intentguard.api import create_app

        with patch.dict(
            os.environ,
            {"INTENTGUARD_DATABASE_URL": "postgresql://unavailable/tenancy"},
            clear=False,
        ), patch(
            "intentguard.api.configured_engine", return_value=seeded_engine()
        ), patch(
            "intentguard.api.configured_tenancy_store",
            side_effect=OSError("database unavailable"),
        ):
            client = TestClient(create_app(authenticator=authenticator()))
            response = client.get(
                "/v1/agents", headers=bearer(subject="operator-1", roles=["operator"])
            )

        self.assertEqual(503, response.status_code)
        self.assertIn("unavailable", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
