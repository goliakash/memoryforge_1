import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
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

# Similarity threshold for Hindsight memory recall (0.0 to 1.0)
DEFAULT_SIMILARITY_THRESHOLD = 0.40
HIGH_CONFIDENCE_THRESHOLD = 0.70
