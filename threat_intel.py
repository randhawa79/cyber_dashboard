import datetime
from config import logger
from database import get_db_connection

def sync_threat_indicators():
    """Aggregates Indicator of Compromise (IOC) telemetry specific to point-of-sale and payment apps."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        iocs = [
            ("198.51.100.42", "IP", "Banking Malware C2 Server", 95),
            ("203.0.113.119", "IP", "POS Skimming Exfiltration Endpoint", 98),
            ("payment-verify-gateway.com", "Domain", "Phishing Landing Portal", 90),
            ("kernel-patch-bypass.exe", "File Hash", "Ransomware Core Payload", 88)
        ]
        
        today = datetime.date.today().isoformat()
        for item in iocs:
            cursor.execute("""
                INSERT OR REPLACE INTO threat_iocs (ioc_value, ioc_type, threat_category, confidence_score, detected_date)
                VALUES (?, ?, ?, ?, ?)
            """, (item[0], item[1], item[2], item[3], today))
            
        conn.commit()
        conn.close()
        logger.info("Threat intelligence repositories enriched successfully.")
    except Exception as e:
        logger.error(f"Error updating infrastructure indicator feeds: {str(e)}")