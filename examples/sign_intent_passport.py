"""Create an offline development Ed25519 key and signed intent passport.

The private key deliberately remains inside this process. A real customer
consent service would hold it in a KMS/HSM and expose only the public key.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from intentguard.intent import encode_public_key, passport_payload, sign_passport
from intentguard.models import IntentPassport


def main() -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    private_key = Ed25519PrivateKey.generate()
    passport = sign_passport(
        IntentPassport(
            intent_id=f"intent_{uuid4().hex}",
            customer_id="customer-01",
            agent_id="travel-01",
            action="book_hotel",
            max_amount=Decimal("18000"),
            currency="INR",
            required_attributes={"city": "BOM", "refundable": True},
            issuer="http://127.0.0.1:9100",
            audience="intentguard-api",
            issued_at=now,
            not_before=now,
            expires_at=now + timedelta(hours=1),
            nonce=f"nonce_{uuid4().hex}",
            key_id="local-consent-2026-08",
        ),
        private_key,
    )
    print(
        json.dumps(
            {
                "key_registration": {
                    "key_id": passport.key_id,
                    "issuer": passport.issuer,
                    "public_key": encode_public_key(private_key.public_key()),
                },
                "passport": {
                    **passport_payload(passport),
                    "signature": passport.signature,
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
