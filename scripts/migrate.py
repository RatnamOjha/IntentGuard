"""Apply IntentGuard's idempotent PostgreSQL migrations in filename order."""

from __future__ import annotations

import os
from pathlib import Path

import psycopg


def main() -> None:
    database_url = os.environ["INTENTGUARD_DATABASE_URL"]
    migration_dir = Path(__file__).parents[1] / "migrations"
    migrations = sorted(migration_dir.glob("*.sql"))
    if not migrations:
        raise RuntimeError(f"No migrations found in {migration_dir}")

    with psycopg.connect(database_url) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                filename TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        for migration in migrations:
            applied = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE filename = %s",
                (migration.name,),
            ).fetchone()
            if applied:
                print(f"already applied: {migration.name}")
                continue
            with connection.transaction():
                connection.execute(migration.read_text(encoding="utf-8"))
                connection.execute(
                    "INSERT INTO schema_migrations (filename) VALUES (%s)",
                    (migration.name,),
                )
            print(f"applied: {migration.name}")


if __name__ == "__main__":
    main()
