"""
PrivacyPilot AI — analysis service.

Design constraints, in priority order:

1. The visited URL never reaches this service. Only the policy text does.
2. Policy text is content-addressed by SHA-256. Two users on the same site send
   the same bytes, so the model is called once and everyone after that gets a
   cache hit. This is what makes the privacy claim survive scrutiny.
3. The model returns findings as booleans against a fixed schema. The extension
   maps those booleans to fixed point deductions, so the score stays
   reproducible even though the summary prose does not.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Load .env if python-dotenv is installed. Optional, so the service still starts
# with plain environment variables and no extra dependency.
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

DB_PATH = os.getenv("PP_DB", "privacypilot.db")
PROVIDER = os.getenv("PP_PROVIDER", "openai").lower()
OPENAI_KEY = os.getenv("OPENAI_API_KEY")
GEMINI_KEY = os.getenv("GEMINI_API_KEY")

app = FastAPI(title="PrivacyPilot AI", version="0.2.0")

# Requests originate from an extension service worker, which sends either
# `Origin: chrome-extension://<id>` or, in some MV3 contexts, `Origin: null`.
# A literal "chrome-extension://*" in allow_origins does NOT work — CORS origin
# entries are exact strings, not globs. The regex below is what actually matches.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["null"],
    allow_origin_regex=r"^(chrome-extension|moz-extension)://.*$",
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    sha256      TEXT PRIMARY KEY,
    payload     TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    hits        INTEGER NOT NULL DEFAULT 0
);
"""


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


with db() as conn:
    conn.executescript(SCHEMA)


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #


class PolicyRequest(BaseModel):
    text: str = Field(min_length=400, max_length=40_000)


class Findings(BaseModel):
    """Booleans only. These map to fixed deductions in the extension."""

    sellsData: Optional[bool] = None
    sharesWithAdvertisers: Optional[bool] = None
    retentionIndefinite: Optional[bool] = None
    noOptOut: Optional[bool] = None


class PolicyResponse(BaseModel):
    dataCollected: str
    dataShared: str
    retention: str
    advertising: str
    userControls: str
    risks: list[str] = []
    readability: str
    findings: Findings
    cached: bool = False


SYSTEM_PROMPT = """You analyse privacy policies for a browser extension that helps people \
understand what they are agreeing to.

Return a single JSON object and nothing else. No markdown fences, no preamble.

Schema:
{
  "dataCollected":   "one or two plain sentences listing what the policy says is collected",
  "dataShared":      "who the data goes to, named where the policy names them",
  "retention":       "how long data is kept, quoting the stated period if there is one",
  "advertising":     "how data is used for advertising or profiling",
  "userControls":    "what the reader can actually opt out of, and how",
  "risks":           ["short flags for the two or three most consequential terms"],
  "readability":     "one of: plain, moderate, dense legalese",
  "findings": {
    "sellsData":             true | false | null,
    "sharesWithAdvertisers": true | false | null,
    "retentionIndefinite":   true | false | null,
    "noOptOut":              true | false | null
  }
}

Rules:
- Use null in findings when the policy genuinely does not address the point. Do not \
guess to fill a gap; a null is more useful to the reader than a confident wrong answer.
- Write the prose fields for someone with no legal training. Short sentences, active \
voice, no hedging.
- Do not editorialise or recommend actions. Describe what the document says.
"""


# --------------------------------------------------------------------------- #
# Providers
# --------------------------------------------------------------------------- #


async def call_openai(text: str) -> dict[str, Any]:
    if not OPENAI_KEY:
        raise HTTPException(503, "OPENAI_API_KEY is not set on the server.")
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_KEY}"},
            json={
                "model": os.getenv("PP_MODEL", "gpt-4o-mini"),
                "temperature": 0,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": text},
                ],
            },
        )
    if response.status_code != 200:
        raise HTTPException(502, f"Model provider returned {response.status_code}.")
    return json.loads(response.json()["choices"][0]["message"]["content"])


async def call_gemini(text: str) -> dict[str, Any]:
    if not GEMINI_KEY:
        raise HTTPException(503, "GEMINI_API_KEY is not set on the server.")
    model = os.getenv("PP_MODEL", "gemini-2.0-flash")
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            params={"key": GEMINI_KEY},
            json={
                "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                "contents": [{"parts": [{"text": text}]}],
                "generationConfig": {"temperature": 0, "responseMimeType": "application/json"},
            },
        )
    if response.status_code != 200:
        raise HTTPException(502, f"Model provider returned {response.status_code}.")
    body = response.json()
    return json.loads(body["candidates"][0]["content"]["parts"][0]["text"])


async def analyse(text: str) -> dict[str, Any]:
    return await (call_gemini(text) if PROVIDER == "gemini" else call_openai(text))


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #


@app.get("/health")
def health() -> dict[str, Any]:
    with db() as conn:
        cached = conn.execute("SELECT COUNT(*) AS n FROM analyses").fetchone()["n"]
        hits = conn.execute("SELECT COALESCE(SUM(hits), 0) AS n FROM analyses").fetchone()["n"]
    return {
        "status": "ok",
        "provider": PROVIDER,
        "key_configured": bool(OPENAI_KEY or GEMINI_KEY),
        "policies_cached": cached,
        "cache_hits": hits,
    }


@app.post("/analyze-policy", response_model=PolicyResponse)
async def analyze_policy(request: PolicyRequest) -> PolicyResponse:
    # Normalise whitespace so trivially different scrapes of the same policy
    # still collide in the cache.
    normalised = " ".join(request.text.split())
    digest = hashlib.sha256(normalised.encode("utf-8")).hexdigest()

    with db() as conn:
        row = conn.execute("SELECT payload FROM analyses WHERE sha256 = ?", (digest,)).fetchone()
        if row:
            conn.execute("UPDATE analyses SET hits = hits + 1 WHERE sha256 = ?", (digest,))
            return PolicyResponse(**json.loads(row["payload"]), cached=True)

    raw = await analyse(normalised)

    payload = {
        "dataCollected": str(raw.get("dataCollected", "Not stated")),
        "dataShared": str(raw.get("dataShared", "Not stated")),
        "retention": str(raw.get("retention", "Not stated")),
        "advertising": str(raw.get("advertising", "Not stated")),
        "userControls": str(raw.get("userControls", "Not stated")),
        "risks": [str(r) for r in raw.get("risks", [])][:4],
        "readability": str(raw.get("readability", "moderate")),
        "findings": Findings(**(raw.get("findings") or {})).model_dump(),
    }

    with db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO analyses (sha256, payload, created_at, hits) VALUES (?, ?, ?, 0)",
            (digest, json.dumps(payload), int(time.time())),
        )

    return PolicyResponse(**payload, cached=False)
