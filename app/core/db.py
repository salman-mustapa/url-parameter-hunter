import logging
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

from app.core.config import settings

logger = logging.getLogger("core.db")

is_sqlite = settings.database_url.startswith("sqlite")
if is_sqlite:
    engine_kwargs = {
        "echo": False,
        "poolclass": NullPool,
        "connect_args": {"check_same_thread": False},
    }
else:
    # PostgreSQL / asyncpg connection pool with high-capacity limits, health pre-ping and recycle
    engine_kwargs = {
        "echo": False,
        "pool_pre_ping": True,
        "pool_recycle": settings.db_pool_recycle,
        "pool_size": settings.db_pool_size,
        "max_overflow": settings.db_max_overflow,
        "pool_timeout": settings.db_pool_timeout,
    }

engine = create_async_engine(settings.database_url, **engine_kwargs)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


from contextlib import asynccontextmanager

@asynccontextmanager
async def async_session_scope():
    session = AsyncSessionLocal()
    try:
        yield session
    except Exception:
        try:
            await session.rollback()
        except Exception:
            pass
        raise
    finally:
        try:
            await session.close()
        except Exception:
            pass


async def get_db():
    session = AsyncSessionLocal()
    try:
        yield session
    except Exception:
        try:
            await session.rollback()
        except Exception:
            pass
        raise
    finally:
        try:
            await session.close()
        except Exception:
            pass


async def ping() -> bool:
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


class Base(DeclarativeBase):
    pass


async def init_db() -> None:
    from app.models import models  # noqa: F401 ensure models registered
    from app.models.models import User
    from app.core.auth import hash_password

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # Dynamic & Explicit Schema Synchronization for all models (V8 §48, V13 Multi-Tenant)
        # Guarantees zero missing columns across SQLite and PostgreSQL
        explicit_columns = [
            # users
            ("users", "tenant_id", "VARCHAR", "VARCHAR REFERENCES tenants(id) ON DELETE SET NULL"),
            # scans
            ("scans", "campaign_id", "VARCHAR", "VARCHAR"),
            ("scans", "tenant_id", "VARCHAR", "VARCHAR REFERENCES tenants(id) ON DELETE SET NULL"),
            ("scans", "project_id", "VARCHAR", "VARCHAR REFERENCES projects(id) ON DELETE SET NULL"),
            ("scans", "checkpoint", "JSON DEFAULT '{}'", "JSON DEFAULT '{}'::json"),
            ("scans", "last_error", "TEXT", "TEXT"),
            ("scans", "heartbeat_at", "TIMESTAMP", "TIMESTAMP WITH TIME ZONE"),
            ("scans", "attempt", "INTEGER DEFAULT 1", "INTEGER DEFAULT 1"),
            ("scans", "priority", "INTEGER DEFAULT 50", "INTEGER DEFAULT 50"),
            ("scans", "user_id", "VARCHAR", "VARCHAR REFERENCES users(id) ON DELETE SET NULL"),
            ("scans", "scope_id", "VARCHAR", "VARCHAR REFERENCES scopes(id) ON DELETE SET NULL"),
            ("scans", "domain_id", "VARCHAR", "VARCHAR REFERENCES domains(id) ON DELETE SET NULL"),
            ("scans", "validation_level", "VARCHAR DEFAULT 'L2_SAFE_ACTIVE'", "VARCHAR DEFAULT 'L2_SAFE_ACTIVE'"),
            ("scans", "authorization_id", "VARCHAR", "VARCHAR"),
            ("scans", "authorization_reference", "VARCHAR", "VARCHAR"),
            ("scans", "operator_id", "VARCHAR", "VARCHAR"),
            ("scans", "allowed_modules", "JSON DEFAULT '[]'", "JSON DEFAULT '[]'::json"),
            ("scans", "allowed_actions", "JSON DEFAULT '[]'", "JSON DEFAULT '[]'::json"),
            ("scans", "active_module_status", "JSON DEFAULT '{}'", "JSON DEFAULT '{}'::json"),
            ("scans", "kill_switch", "BOOLEAN DEFAULT 0", "BOOLEAN DEFAULT FALSE"),
            ("scans", "expires_at", "TIMESTAMP", "TIMESTAMP WITH TIME ZONE"),
            ("scans", "progress", "JSON DEFAULT '{}'", "JSON DEFAULT '{}'::json"),
            # assets
            ("assets", "parent_id", "VARCHAR", "VARCHAR REFERENCES assets(id) ON DELETE SET NULL"),
            ("assets", "domain_id", "VARCHAR", "VARCHAR REFERENCES domains(id) ON DELETE SET NULL"),
            ("assets", "liveness_status", "VARCHAR DEFAULT 'ACTIVE'", "VARCHAR DEFAULT 'ACTIVE'"),
            ("assets", "discovered_from", "JSON DEFAULT '[]'", "JSON DEFAULT '[]'::json"),
            ("assets", "metadata", "JSON DEFAULT '{}'", "JSON DEFAULT '{}'::json"),
            # urls
            ("urls", "query", "TEXT", "TEXT"),
            ("urls", "status_code", "INTEGER", "INTEGER"),
            ("urls", "content_type", "VARCHAR", "VARCHAR"),
            ("urls", "title", "VARCHAR", "VARCHAR"),
            ("urls", "redirect_chain", "JSON DEFAULT '[]'", "JSON DEFAULT '[]'::json"),
            ("urls", "auth_context_id", "VARCHAR", "VARCHAR"),
            ("urls", "first_seen", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP", "TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP"),
            ("urls", "last_seen", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP", "TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP"),
            # parameters
            ("parameters", "source", "VARCHAR DEFAULT 'crawler'", "VARCHAR DEFAULT 'crawler'"),
            ("parameters", "observed_values_hash", "VARCHAR", "VARCHAR"),
            ("parameters", "confidence", "FLOAT DEFAULT 1.0", "FLOAT DEFAULT 1.0"),
            # technologies
            ("technologies", "category", "VARCHAR", "VARCHAR"),
            ("technologies", "version", "VARCHAR", "VARCHAR"),
            ("technologies", "cpe", "VARCHAR", "VARCHAR"),
            ("technologies", "confidence", "FLOAT DEFAULT 0.0", "FLOAT DEFAULT 0.0"),
            ("technologies", "evidence", "TEXT", "TEXT"),
            # findings
            ("findings", "finding_code", "VARCHAR", "VARCHAR"),
            ("findings", "domain_id", "VARCHAR", "VARCHAR REFERENCES domains(id) ON DELETE SET NULL"),
            ("findings", "asset_id", "VARCHAR", "VARCHAR REFERENCES assets(id) ON DELETE SET NULL"),
            ("findings", "url_id", "VARCHAR", "VARCHAR REFERENCES urls(id) ON DELETE SET NULL"),
            ("findings", "cwe_id", "VARCHAR", "VARCHAR"),
            ("findings", "cve_id", "VARCHAR", "VARCHAR"),
            ("findings", "cvss_score", "FLOAT", "FLOAT"),
            ("findings", "dedup_key", "VARCHAR", "VARCHAR"),
            ("findings", "description", "TEXT", "TEXT"),
            ("findings", "impact", "TEXT", "TEXT"),
            ("findings", "technical_details", "TEXT", "TEXT"),
            ("findings", "remediation", "TEXT", "TEXT"),
            ("findings", "evidence", "JSON DEFAULT '{}'", "JSON DEFAULT '{}'::json"),
            ("findings", "reproducibility_meta", "JSON DEFAULT '{}'", "JSON DEFAULT '{}'::json"),
            ("findings", "evidence_level", "VARCHAR DEFAULT 'E0'", "VARCHAR DEFAULT 'E0'"),
            ("findings", "evidence_score", "INTEGER DEFAULT 10", "INTEGER DEFAULT 10"),
            ("findings", "impact_matrix", "JSON DEFAULT '{}'", "JSON DEFAULT '{}'::json"),
            ("findings", "validation_status", "VARCHAR DEFAULT 'DISCOVERED'", "VARCHAR DEFAULT 'DISCOVERED'"),
            ("findings", "exploitability_state", "VARCHAR DEFAULT 'CANDIDATE'", "VARCHAR DEFAULT 'CANDIDATE'"),
            ("findings", "priority", "VARCHAR DEFAULT 'P2'", "VARCHAR DEFAULT 'P2'"),
            ("findings", "rule_version", "VARCHAR DEFAULT 'v8.0.0'", "VARCHAR DEFAULT 'v8.0.0'"),
            ("findings", "root_cause", "TEXT", "TEXT"),
            ("findings", "preconditions", "JSON DEFAULT '[]'", "JSON DEFAULT '[]'::json"),
            ("findings", "expected_result", "TEXT", "TEXT"),
            ("findings", "actual_result", "TEXT", "TEXT"),
            ("findings", "executive_explanation", "TEXT", "TEXT"),
            ("findings", "business_impact", "TEXT", "TEXT"),
            # reports
            ("reports", "domain_id", "VARCHAR", "VARCHAR REFERENCES domains(id) ON DELETE SET NULL"),
            ("reports", "report_type", "VARCHAR DEFAULT 'executive'", "VARCHAR DEFAULT 'executive'"),
            ("reports", "report_format", "VARCHAR DEFAULT 'markdown'", "VARCHAR DEFAULT 'markdown'"),
            ("reports", "view_perspective", "VARCHAR DEFAULT 'customer'", "VARCHAR DEFAULT 'customer'"),
            ("reports", "executive_summary", "TEXT", "TEXT"),
            ("reports", "stats_summary", "JSON DEFAULT '{}'", "JSON DEFAULT '{}'::json"),
            ("reports", "storage_path", "TEXT", "TEXT"),
            ("reports", "is_redacted", "BOOLEAN DEFAULT 1", "BOOLEAN DEFAULT TRUE"),
            # retests
            ("retests", "operator_id", "VARCHAR", "VARCHAR"),
            ("retests", "status", "VARCHAR DEFAULT 'PENDING'", "VARCHAR DEFAULT 'PENDING'"),
            ("retests", "before_evidence_id", "VARCHAR", "VARCHAR REFERENCES evidence(id) ON DELETE SET NULL"),
            ("retests", "after_evidence_id", "VARCHAR", "VARCHAR REFERENCES evidence(id) ON DELETE SET NULL"),
            ("retests", "comparison_result", "JSON DEFAULT '{}'", "JSON DEFAULT '{}'::json"),
            ("retests", "notes", "TEXT", "TEXT"),
            ("retests", "completed_at", "TIMESTAMP", "TIMESTAMP WITH TIME ZONE"),
            # evidence
            ("evidence", "request_id", "VARCHAR", "VARCHAR"),
            ("evidence", "response_hash", "VARCHAR", "VARCHAR"),
            ("evidence", "sha256_hash", "VARCHAR", "VARCHAR"),
            ("evidence", "collector_version", "VARCHAR DEFAULT 'v8.0.0'", "VARCHAR DEFAULT 'v8.0.0'"),
            ("evidence", "campaign_id", "VARCHAR", "VARCHAR"),
            ("evidence", "evidence_type_v5", "VARCHAR DEFAULT 'observation'", "VARCHAR DEFAULT 'observation'"),
            ("evidence", "evidence_type_v8", "VARCHAR DEFAULT 'observation'", "VARCHAR DEFAULT 'observation'"),
            ("evidence", "storage_path", "TEXT", "TEXT"),
            ("evidence", "provenance", "JSON DEFAULT '{}'", "JSON DEFAULT '{}'::json"),
            ("evidence", "confidence", "VARCHAR DEFAULT 'DIRECT_OBSERVATION'", "VARCHAR DEFAULT 'DIRECT_OBSERVATION'"),
            # audit_logs
            ("audit_logs", "actor", "VARCHAR DEFAULT 'system'", "VARCHAR DEFAULT 'system'"),
            ("audit_logs", "target", "VARCHAR", "VARCHAR"),
            ("audit_logs", "scope", "VARCHAR", "VARCHAR"),
            ("audit_logs", "authorization_ref", "VARCHAR", "VARCHAR"),
            ("audit_logs", "tool_name", "VARCHAR", "VARCHAR"),
            ("audit_logs", "tool_version", "VARCHAR", "VARCHAR"),
            ("audit_logs", "ai_decision_id", "VARCHAR", "VARCHAR"),
            ("audit_logs", "result_status", "VARCHAR DEFAULT 'SUCCESS'", "VARCHAR DEFAULT 'SUCCESS'"),
            ("audit_logs", "evidence_id", "VARCHAR", "VARCHAR"),
            ("audit_logs", "details", "JSON DEFAULT '{}'", "JSON DEFAULT '{}'::json"),
        ]

        if is_sqlite:
            for table_name, col_name, sqlite_type, _ in explicit_columns:
                try:
                    await conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {sqlite_type}"))
                except Exception:
                    pass
        else:
            for table_name, col_name, _, pg_type in explicit_columns:
                try:
                    await conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS {col_name} {pg_type}"))
                except Exception:
                    pass

            # Indexes for PostgreSQL
            indexes = [
                "CREATE INDEX IF NOT EXISTS ix_scans_user_id ON scans(user_id)",
                "CREATE INDEX IF NOT EXISTS ix_scans_campaign_id ON scans(campaign_id)",
                "CREATE INDEX IF NOT EXISTS ix_findings_finding_code ON findings(finding_code)",
                "CREATE INDEX IF NOT EXISTS ix_findings_dedup_key ON findings(dedup_key)",
                "CREATE INDEX IF NOT EXISTS ix_findings_evidence_level ON findings(evidence_level)",
                "CREATE INDEX IF NOT EXISTS ix_findings_priority ON findings(priority)",
                "CREATE INDEX IF NOT EXISTS ix_evidence_sha256 ON evidence(sha256_hash)",
            ]
            for idx_sql in indexes:
                try:
                    await conn.execute(text(idx_sql))
                except Exception:
                    pass

            # Schema migration: findings.confidence was originally FLOAT, now is VARCHAR
            try:
                await conn.execute(text("""
                    DO $$
                    BEGIN
                        IF EXISTS (
                            SELECT 1 FROM information_schema.columns
                            WHERE table_name = 'findings'
                              AND column_name = 'confidence'
                              AND data_type = 'double precision'
                        ) THEN
                            ALTER TABLE findings ALTER COLUMN confidence TYPE character varying USING confidence::text;
                            UPDATE findings SET confidence = 'CONFIRMED' WHERE confidence IS NULL OR confidence ~ '^[0-9]';
                        END IF;
                    END $$;
                """))
            except Exception:
                pass

    # Seed strictly only requested initial accounts (Admin: s4lm4n, User: mances)
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select, delete

        # Clean up any non-default accounts if present
        await db.execute(delete(User).where(User.username.in_(["admin", "hunter"])))

        # 1. Admin: s4lm4n / S4lm4n.Must4p4
        salman = (await db.execute(select(User).where(User.username == "s4lm4n"))).scalar_one_or_none()
        if not salman:
            db.add(User(
                username="s4lm4n",
                email="salman@hunter.local",
                hashed_password=hash_password("S4lm4n.Must4p4"),
                role="admin",
                is_active=True,
            ))
        else:
            salman.hashed_password = hash_password("S4lm4n.Must4p4")
            salman.role = "admin"
            salman.is_active = True

        # 2. Testing User: mances / tOOr12345*
        mances = (await db.execute(select(User).where(User.username == "mances"))).scalar_one_or_none()
        if not mances:
            db.add(User(
                username="mances",
                email="mances@hunter.local",
                hashed_password=hash_password("tOOr12345*"),
                role="user",
                is_active=True,
            ))
        else:
            mances.hashed_password = hash_password("tOOr12345*")
            mances.role = "user"
            mances.is_active = True

        await db.commit()