"""Global configuration — loaded from .env"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

# Database
DB_URL = os.getenv("AARCHAI_DB_URL", "postgresql://aarchai:aarchai@localhost:5432/aarchai")

# Redis / Celery
REDIS_URL = os.getenv("AARCHAI_REDIS_URL", "redis://localhost:6379/0")

# API keys
SHODAN_API_KEY     = os.getenv("SHODAN_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
NVD_API_KEY        = os.getenv("NVD_API_KEY", "")

# LLM
LLM_PROVIDER   = os.getenv("LLM_PROVIDER", "stub")
OLLAMA_URL     = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL", "llama3")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL   = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
GOOGLE_MODEL   = os.getenv("GOOGLE_MODEL", "gemini-2.5-flash")

# Paths & timeouts
TOOL_TIMEOUT = int(os.getenv("TOOL_TIMEOUT", "300"))
OUTPUT_DIR   = os.getenv("OUTPUT_DIR", "./reports")
BASE_DIR     = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
