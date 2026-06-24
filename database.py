import sqlite3
import pandas as pd
from config import DB_PATH, logger

def get_db_connection():
    """Establishes and returns a connection to the SQLite local database."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    """Creates tables with proper indices and unique constraints if they don't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Vulnerabilities Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        cve_id TEXT PRIMARY KEY,
        cvss_score REAL,
        epss_score REAL,
        is_exploited INTEGER DEFAULT 0,
        vendor TEXT,
        product TEXT,
        description TEXT,
        published_date TEXT
    )""")
    
    # Cyber News Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS news (
        url TEXT PRIMARY KEY,
        title TEXT,
        source TEXT,
        summary TEXT,
        published_date TEXT
    )""")
    
    # Regulatory Alerts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS regulatory_alerts (
        alert_id TEXT PRIMARY KEY,
        source TEXT,
        title TEXT,
        summary TEXT,
        compliance_impact TEXT,
        recommended_action TEXT,
        published_date TEXT
    )""")
    
    # Threat Indicators Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_iocs (
        ioc_value TEXT PRIMARY KEY,
        ioc_type TEXT,
        threat_category TEXT,
        confidence_score INTEGER,
        detected_date TEXT
    )""")
    
    conn.commit()
    conn.close()
    logger.info("Database schemas verified and initialized successfully.")

def query_to_dataframe(query, params=()):
    """Executes a read query and converts results cleanly to a Pandas DataFrame."""
    conn = get_db_connection()
    try:
        df = pd.read_sql_query(query, conn, params=params)
        return df
    except Exception as e:
        logger.error(f"Database query execution failure: {str(e)}")
        return pd.DataFrame()
    finally:
        conn.close()