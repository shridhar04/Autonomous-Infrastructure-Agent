"""
Database migration runner — applies Alembic migrations and initializes
TimescaleDB hypertables for time-series analytics.
Run: python scripts/migrate.py
"""

import asyncio
import subprocess
import sys
from pathlib import Path


def run_alembic_migrations():
    """Run pending Alembic migrations."""
    print("Running Alembic migrations...")
    result = subprocess.run(
        ["alembic", "upgrade", "head"],
        cwd=Path(__file__).parent.parent,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"Migration failed:\n{result.stderr}")
        sys.exit(1)
    print(f"Migrations applied:\n{result.stdout}")


async def setup_timescale():
    """Convert findings and scans tables to TimescaleDB hypertables."""
    import asyncpg
    from config.settings import settings

    conn = await asyncpg.connect(settings.DATABASE_URL.replace("+asyncpg", ""))

    try:
        # Create hypertable for time-series scan data
        await conn.execute("""
            SELECT create_hypertable(
                'scans', 'started_at',
                if_not_exists => TRUE,
                chunk_time_interval => INTERVAL '1 week'
            );
        """)
        print("TimescaleDB hypertable created for 'scans'")

        await conn.execute("""
            SELECT create_hypertable(
                'findings', 'created_at',
                if_not_exists => TRUE,
                chunk_time_interval => INTERVAL '1 week'
            );
        """)
        print("TimescaleDB hypertable created for 'findings'")

        # Add compression policy — compress chunks older than 30 days
        await conn.execute("""
            SELECT add_compression_policy('scans', INTERVAL '30 days', if_not_exists => TRUE);
            SELECT add_compression_policy('findings', INTERVAL '30 days', if_not_exists => TRUE);
        """)
        print("Compression policies applied")

    except Exception as e:
        print(f"TimescaleDB setup note: {e} (may already exist)")
    finally:
        await conn.close()



if __name__ == "__main__":
    run_alembic_migrations()
    asyncio.run(setup_timescale())
    print("\nDatabase setup complete.")    