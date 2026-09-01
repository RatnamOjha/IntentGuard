"""Seed deterministic demo entities after the database migrations complete."""

from __future__ import annotations

from intentguard.api import configured_engine, seed_demo_engine


def main() -> None:
    engine = configured_engine()
    try:
        seed_demo_engine(engine)
        print("IntentGuard demo data is ready.")
    finally:
        engine.close()


if __name__ == "__main__":
    main()
