from __future__ import annotations

import sys
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from intentguard.auth import (  # noqa: E402
    AuthenticationError,
    AuthorizationError,
    JwksAuthenticator,
)
from tests.jwt_test_support import AUDIENCE, ISSUER, JWKS, token  # noqa: E402


class JwksAuthenticatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.auth = JwksAuthenticator(
            issuer=ISSUER, audience=AUDIENCE, jwks=JWKS, minimum_rsa_bits=512
        )

    def test_valid_signature_and_identity_claims(self) -> None:
        principal = self.auth.authenticate(
            "Bearer "
            + token(
                subject="agent-user",
                roles=["agent"],
                agent_id="travel-01",
                customer_id="customer-01",
            )
        )

        self.assertEqual("agent-user", principal.subject)
        self.assertEqual("travel-01", principal.agent_id)
        self.assertEqual("customer-01", principal.customer_id)
        self.assertEqual(frozenset({"agent"}), principal.roles)

    def test_missing_token(self) -> None:
        with self.assertRaises(AuthenticationError):
            self.auth.authenticate(None)

    def test_invalid_signature(self) -> None:
        encoded = token(roles=["agent"])
        header, payload, signature = encoded.split(".")
        replacement = "A" if signature[0] != "A" else "B"
        tampered = f"{header}.{payload}.{replacement}{signature[1:]}"
        with self.assertRaises(AuthenticationError):
            self.auth.authenticate("Bearer " + tampered)

    def test_expired_token(self) -> None:
        with self.assertRaisesRegex(AuthenticationError, "expired"):
            self.auth.authenticate(
                "Bearer " + token(expires_delta=timedelta(seconds=-1))
            )

    def test_wrong_role(self) -> None:
        principal = self.auth.authenticate(
            "Bearer " + token(roles=["customer"])
        )
        with self.assertRaises(AuthorizationError):
            self.auth.require_roles(principal, frozenset({"operator"}))

    def test_keycloak_realm_roles_are_supported(self) -> None:
        principal = self.auth.authenticate(
            "Bearer "
            + token(roles=[], realm_access={"roles": ["reviewer"]})
        )
        self.assertIn("reviewer", principal.roles)


if __name__ == "__main__":
    unittest.main()
