"""Vercel Python function entry point: serves the whole FastAPI app (see vercel.json rewrites)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import app  # noqa: E402,F401
