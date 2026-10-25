import os
import random
from datetime import datetime, timedelta
from sqlalchemy import create_engine, text

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "itgc_db")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "secretpassword")
DB_PORT = os.getenv("DB_PORT", "5432")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
engine = create_engine(DATABASE_URL)

def seed_audit_logs():
    with engine.begin() as conn:
        print("Creating audit logs table...")
        conn.execute(text("""
            DROP TABLE IF EXISTS database_audit_logs;
            CREATE TABLE database_audit_logs (
                log_id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP,
                username VARCHAR(100),
                event_type VARCHAR(100),
                raw_log TEXT,
                risk_level VARCHAR(50)
            );
        """))

        print("Generating mock ITGC audit log entries...")
        base_time = datetime.now() - timedelta(days=3)
        
        users = ["app_user", "db_admin", "rogue_dba", "finance_service", "root_sys", "guest"]
        actions = [
            ("LOGIN_FAILED", "WARNING", "Failed password authentication for user '{user}' from IP 192.168.1.{ip}"),
            ("PRIVILEGE_ESCALATION", "HIGH", "User '{user}' granted ALTER SYSTEM / SUPERUSER role privileges."),
            ("DDL_EXECUTION", "MEDIUM", "User '{user}' executed DROP TABLE production_ledger;"),
            ("LOGIN_SUCCESS", "LOW", "Successful connection established for user '{user}'."),
            ("UNAUTHORIZED_ACCESS", "HIGH", "User '{user}' attempted access to restricted system catalog table pg_shadow.")
        ]

        log_records = []
        for i in range(1, 120):
            user = random.choice(users)
            action_type, risk, template = random.choice(actions)
            
            ip = random.randint(10, 200)
            raw_message = template.format(user=user, ip=ip)
            log_time = base_time + timedelta(minutes=i*35)
            
            if user in ["root_sys", "rogue_dba"] and action_type in ["PRIVILEGE_ESCALATION", "DDL_EXECUTION"]:
                risk = "CRITICAL"

            log_records.append({
                "timestamp": log_time,
                "username": user,
                "event_type": action_type,
                "raw_log": f"[{log_time.strftime('%Y-%m-%d %H:%M:%S')}] [{action_type}] {raw_message}",
                "risk_level": risk
            })

        for r in log_records:
            conn.execute(text("""
                INSERT INTO database_audit_logs (timestamp, username, event_type, raw_log, risk_level)
                VALUES (:timestamp, :username, :event_type, :raw_log, :risk_level)
            """), r)

        print(f"Seeded {len(log_records)} ITGC audit log records successfully.")

if __name__ == "__main__":
    seed_audit_logs()
