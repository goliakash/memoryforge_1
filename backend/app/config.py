import os
from pathlib import Path
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

INCIDENTS_FILE = DATA_DIR / "incidents.json"
MEMORY_FILE = DATA_DIR / "hindsight_memory.json"
GRAPH_FILE = DATA_DIR / "memory_graph.json"

PROJECT_NAME = "Hindsight SecOps & Compliance Memory Agent"
PROJECT_TAGLINE = "Turning Security Incidents into Persistent Organizational Memory"
VERSION = "1.0.0"

# Optional LLM API Key (if provided by user in .env or environment)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Hindsight Cloud Configuration
HINDSIGHT_API_URL = os.getenv(
    "HINDSIGHT_API_URL",
    "https://api.hindsight.vectorize.io"
)

HINDSIGHT_API_KEY = os.getenv("HINDSIGHT_API_KEY", "")

HINDSIGHT_BANK_ID = os.getenv(
    "HINDSIGHT_BANK_ID",
    "memoryforge-secops"
)

HINDSIGHT_CLOUD_ENABLED = bool(HINDSIGHT_API_KEY)

# Similarity threshold for Hindsight memory recall (0.0 to 1.0)
DEFAULT_SIMILARITY_THRESHOLD = 0.40
HIGH_CONFIDENCE_THRESHOLD = 0.70

# CORS Configuration
ALLOWED_ORIGINS_ENV = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:8000,http://127.0.0.1:8000,http://localhost:3000,http://localhost:5173"
)
ALLOWED_ORIGINS = [origin.strip() for origin in ALLOWED_ORIGINS_ENV.split(",") if origin.strip()]
ALLOW_CREDENTIALS = True if "*" not in ALLOWED_ORIGINS else False
