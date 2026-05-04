import os
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")


def get_connection():
    return psycopg2.connect(DATABASE_URL)


def init_db():
    """
    Creates all tables if they don't exist yet.
    Run this once on startup.
    """
    conn = get_connection()
    cur = conn.cursor()

    # Sites table — one row per registered website
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sites (
            id          SERIAL PRIMARY KEY,
            name        TEXT NOT NULL,
            api_key     TEXT NOT NULL UNIQUE,
            owner_email TEXT NOT NULL,
            created_at  TIMESTAMP DEFAULT NOW()
        )
    """)

    # Blacklist table — one row per blocked IP, per site
    cur.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            id          SERIAL PRIMARY KEY,
            site_id     INTEGER REFERENCES sites(id),
            ip_address  TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            blocked_at  TIMESTAMP DEFAULT NOW(),
            UNIQUE(site_id, ip_address)
        )
    """)

    # Events log — every request Sentinel checks gets logged here
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id          SERIAL PRIMARY KEY,
            site_id     INTEGER REFERENCES sites(id),
            ip_address  TEXT NOT NULL,
            payload     TEXT NOT NULL,
            decision    TEXT NOT NULL,
            reason      TEXT,
            confidence  FLOAT,
            checked_at  TIMESTAMP DEFAULT NOW()
        )
    """)

    conn.commit()
    cur.close()
    conn.close()
    print("[DB] Tables ready.")


def is_blacklisted(site_id: int, ip: str) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT 1 FROM blacklist WHERE site_id = %s AND ip_address = %s",
        (site_id, ip)
    )
    result = cur.fetchone()
    cur.close()
    conn.close()
    return result is not None


def add_to_blacklist(site_id: int, ip: str, attack_type: str):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO blacklist (site_id, ip_address, attack_type)
            VALUES (%s, %s, %s)
            ON CONFLICT (site_id, ip_address) DO NOTHING
            """,
            (site_id, ip, attack_type)
        )
        conn.commit()
    except Exception as e:
        print(f"[DB] Blacklist insert error: {e}")
    finally:
        cur.close()
        conn.close()


def log_event(site_id: int, ip: str, payload: str,
              decision: str, reason: str, confidence: float):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO events
                (site_id, ip_address, payload, decision, reason, confidence)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (site_id, ip, payload, decision, reason, confidence)
        )
        conn.commit()
    except Exception as e:
        print(f"[DB] Event log error: {e}")
    finally:
        cur.close()
        conn.close()


def get_site_by_api_key(api_key: str) -> dict | None:
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT * FROM sites WHERE api_key = %s",
        (api_key,)
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    return dict(row) if row else None


def register_site(name: str, owner_email: str, api_key: str) -> dict:
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        INSERT INTO sites (name, owner_email, api_key)
        VALUES (%s, %s, %s)
        RETURNING *
        """,
        (name, owner_email, api_key)
    )
    row = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return dict(row)


def get_blacklist_for_site(site_id: int) -> list:
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT ip_address, attack_type, blocked_at
        FROM blacklist
        WHERE site_id = %s
        ORDER BY blocked_at DESC
        """,
        (site_id,)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(r) for r in rows]


def remove_from_blacklist(site_id: int, ip: str) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM blacklist WHERE site_id = %s AND ip_address = %s",
        (site_id, ip)
    )
    deleted = cur.rowcount > 0
    conn.commit()
    cur.close()
    conn.close()
    return deleted


def get_recent_events(site_id: int, limit: int = 50) -> list:
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT ip_address, payload, decision, reason, confidence, checked_at
        FROM events
        WHERE site_id = %s
        ORDER BY checked_at DESC
        LIMIT %s
        """,
        (site_id, limit)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(r) for r in rows]