import os
import logging
from pathlib import Path
import streamlit as st

# Directory Initializations
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
REPORT_DIR = BASE_DIR / "reports"

for folder in [DATA_DIR, LOG_DIR, REPORT_DIR]:
    folder.mkdir(parents=True, exist_ok=True)

# Logging Configurations
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "cyber_dashboard.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("CyberDashboard")

# Database Path
DB_PATH = DATA_DIR / "cyber_dashboard.db"

# API Key Retrieval
def get_gemini_api_key():
    """Retrieves the Gemini API Key securely from Streamlit Secrets or Environment Variables."""
    if "GEMINI_API_KEY" in st.secrets:
        return st.secrets["GEMINI_API_KEY"]
    return os.getenv("GEMINI_API_KEY", "")