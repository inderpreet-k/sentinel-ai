import os
import secrets
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

from api.db import (
    init_db,
    get_site_by_api_key,
    register_site,
    is_blacklisted,
    add_to_blacklist,
    remove_from_blacklist,
    log_event,
    get_blacklist_for_site,
    get_recent_events,
)
from api.detector import load_models, analyze


# ---------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[Sentinel] Starting up...")
    init_db()
    load_models()
    print("[Sentinel] Ready.")
    yield
    print("[Sentinel] Shutting down.")


app = FastAPI(
    title="Sentinel AI",
    description="ML-powered security API — drop-in protection for any website.",
    version="2.0.0",
    lifespan=lifespan,
)

# Allow any website to call this API from a browser
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------
class CheckRequest(BaseModel):
    ip: str
    payload: dict | str
    user_agent: str = ""


class RegisterRequest(BaseModel):
    name: str
    owner_email: str


class UnblockRequest(BaseModel):
    ip: str


# ---------------------------------------------------------------
# Auth helper — every protected route calls this
# ---------------------------------------------------------------
def get_current_site(x_api_key: str = Header(...)):
    site = get_site_by_api_key(x_api_key)
    if not site:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    return site


# ---------------------------------------------------------------
# Routes
# ---------------------------------------------------------------
@app.get("/")
def root():
    return {
        "service": "Sentinel AI",
        "version": "2.0.0",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/register")
def register(req: RegisterRequest):
    """
    Register a new website and get an API key back.
    No auth needed — this is the signup endpoint.
    """
    api_key = "sk-" + secrets.token_urlsafe(32)
    site = register_site(
        name=req.name,
        owner_email=req.owner_email,
        api_key=api_key,
    )
    return {
        "message": "Site registered successfully.",
        "site_id": site["id"],
        "site_name": site["name"],
        "api_key": api_key,
        "warning": "Save your API key now — it will not be shown again.",
    }


@app.post("/check")
def check(req: CheckRequest, site: dict = Depends(get_current_site)):
    """
    Main endpoint. Send a payload here, get back allow/block.
    Include header:  X-Api-Key: sk-your-key-here
    """
    site_id = site["id"]

    # 1. Check blacklist first (fastest path)
    if is_blacklisted(site_id, req.ip):
        return {
            "decision": "block",
            "reason": "IP is blacklisted",
            "confidence": 1.0,
            "ip": req.ip,
        }

    # 2. Run ML + rules analysis
    result = analyze(req.payload)

    # 3. If attack detected, add to blacklist
    if result["decision"] == "block":
        add_to_blacklist(site_id, req.ip, result["reason"])

    # 4. Log every event
    log_event(
        site_id=site_id,
        ip=req.ip,
        payload=str(req.payload),
        decision=result["decision"],
        reason=result["reason"],
        confidence=result["confidence"],
    )

    return {
        **result,
        "ip": req.ip,
    }


@app.get("/blacklist")
def blacklist(site: dict = Depends(get_current_site)):
    """
    Get all blocked IPs for your site.
    """
    entries = get_blacklist_for_site(site["id"])
    return {
        "site": site["name"],
        "blocked_count": len(entries),
        "entries": entries,
    }


@app.delete("/blacklist")
def unblock(req: UnblockRequest, site: dict = Depends(get_current_site)):
    """
    Remove an IP from your site's blacklist.
    """
    removed = remove_from_blacklist(site["id"], req.ip)
    if not removed:
        raise HTTPException(status_code=404, detail="IP not found in blacklist.")
    return {"message": f"{req.ip} has been unblocked."}


@app.get("/events")
def events(site: dict = Depends(get_current_site)):
    """
    Get the last 50 requests Sentinel checked for your site.
    """
    rows = get_recent_events(site["id"])
    return {
        "site": site["name"],
        "event_count": len(rows),
        "events": rows,
    }


@app.get("/me")
def me(site: dict = Depends(get_current_site)):
    """
    Returns your site info (minus the API key).
    """
    return {
        "site_id": site["id"],
        "name": site["name"],
        "owner_email": site["owner_email"],
        "created_at": str(site["created_at"]),
    }