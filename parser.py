import pandas as pd
from sqlalchemy import create_engine

def get_engine(host="localhost"):
    return create_engine(f"postgresql://postgres:secretpassword@{host}:5432/itgc_db")

def fetch_logs(engine, risk_filter=None):
    query = "SELECT * FROM database_audit_logs"
    if risk_filter and risk_filter != "ALL":
        query += f" WHERE risk_level = '{risk_filter}'"
    query += " ORDER BY timestamp DESC;"
    return pd.read_sql(query, engine)

def get_risk_summary(engine):
    query = """
        SELECT risk_level, COUNT(*) as count
        FROM database_audit_logs
        GROUP BY risk_level;
    """
    return pd.read_sql(query, engine)

def get_top_violators(engine):
    query = """
        SELECT username, COUNT(*) as violation_count
        FROM database_audit_logs
        WHERE risk_level IN ('HIGH', 'CRITICAL', 'WARNING')
        GROUP BY username
        ORDER BY violation_count DESC;
    """
    return pd.read_sql(query, engine)
