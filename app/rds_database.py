
"""Read-only FlowSense RDS connection using AWS IAM authentication."""

import os

import boto3
from dotenv import load_dotenv
from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url

load_dotenv()

RAW_DATABASE_URL = os.getenv("FLOW_SENSE_DATABASE_URL", "").strip()
AWS_REGION = os.getenv("AWS_REGION", "").strip()
AWS_PROFILE = os.getenv("AWS_PROFILE", "").strip() or None

if not RAW_DATABASE_URL:
    raise RuntimeError("FLOW_SENSE_DATABASE_URL is not configured")

if not AWS_REGION:
    raise RuntimeError("AWS_REGION is not configured")

if RAW_DATABASE_URL.startswith("postgres://"):
    RAW_DATABASE_URL = RAW_DATABASE_URL.replace(
        "postgres://", "postgresql://", 1
    )

parsed_url = make_url(RAW_DATABASE_URL)

if not parsed_url.host or not parsed_url.username or not parsed_url.database:
    raise RuntimeError("FLOW_SENSE_DATABASE_URL is missing required connection details")

DB_HOST = parsed_url.host
DB_PORT = parsed_url.port or 5432
DB_USERNAME = parsed_url.username

# Do not store the database password in the SQLAlchemy engine.
# IAM authentication supplies a short-lived token for each new connection.
engine_url = parsed_url.set(
    drivername="postgresql+psycopg",
    password=None,
)

aws_session = boto3.Session(
    profile_name=AWS_PROFILE,
    region_name=AWS_REGION,
)

rds_client = aws_session.client("rds", region_name=AWS_REGION)

rds_engine = create_engine(
    engine_url,
    connect_args={
        "sslmode": "require",
        # Enforce read-only transactions at the PostgreSQL connection level.
        "options": "-c default_transaction_read_only=on",
    },
    pool_pre_ping=True,
    pool_recycle=840,
    pool_size=3,
    max_overflow=2,
)


@event.listens_for(rds_engine, "do_connect")
def generate_iam_auth_token(dialect, conn_rec, cargs, cparams):
    """Generate a fresh IAM token whenever SQLAlchemy opens a connection."""
    cparams["password"] = rds_client.generate_db_auth_token(
        DBHostname=DB_HOST,
        Port=DB_PORT,
        DBUsername=DB_USERNAME,
        Region=AWS_REGION,
    )


def test_rds_connection() -> dict:
    """Verify connectivity and confirm the session is read-only."""
    with rds_engine.connect() as connection:
        result = connection.execute(
            text(
                "SELECT current_database() AS database_name, "
                "current_user AS database_user, "
                "current_setting('transaction_read_only') AS read_only"
            )
        ).mappings().one()

        return {
            "connected": True,
            "database": result["database_name"],
            "database_user": result["database_user"],
            "read_only": result["read_only"],
        }
