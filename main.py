from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from verifier import EmailVerifier
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import MAX_THREADS
from auth import (
    users_col, hash_password, verify_password, create_token,
    get_current_user, require_approved, require_admin, seed_main_admin, db
)
from bson import ObjectId
from datetime import datetime
from typing import Optional
import pandas as pd
import uuid
import io
import re
import time

app = FastAPI(title="MailClean API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    allow_credentials=False,
    expose_headers=["Content-Disposition"],
)

verifier = EmailVerifier()
jobs     = {}

from routes_dashboard import router as dashboard_router
from routes_leads      import router as leads_router

app.include_router(dashboard_router)
app.include_router(leads_router)


@app.on_event("startup")
async def startup():
    seed_main_admin()


# ── Helpers ───────────────────────────────────────────────────────────────────

def log_verification(user, email_count: int, source: str = "single"):
    db["verify_logs"].insert_one({
        "user_id":    str(user["_id"]),
        "user_name":  user.get("name", ""),
        "user_email": user.get("email", ""),
        "email_count": email_count,
        "source":      source,
        "sent_at":     datetime.utcnow(),
    })
    users_col.update_one(
        {"_id": user["_id"]},
        {"$inc": {"emails_verified": email_count}}
    )


# ── Auth ──────────────────────────────────────────────────────────────────────

class SignupRequest(BaseModel):
    name: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/auth/signup")
async def signup(payload: SignupRequest):
    if not payload.email or "@" not in payload.email:
        raise HTTPException(400, detail="Invalid email address")
    if not payload.name or len(payload.name.strip()) < 2:
        raise HTTPException(400, detail="Name must be at least 2 characters")
    if len(payload.password) < 6:
        raise HTTPException(400, detail="Password must be at least 6 characters")

    existing = users_col.find_one({"email": payload.email.lower().strip()})
    if existing:
        raise HTTPException(400, detail="Email already registered")

    user = {
        "email":           payload.email.lower().strip(),
        "password":        hash_password(payload.password),
        "name":            payload.name.strip(),
        "role":            "user",
        "status":          "pending",
        "created_at":      datetime.utcnow(),
        "emails_verified": 0,
        "emails_scouted":  0,
        "batches_sent":    0,
        "last_active":     None,
    }
    result = users_col.insert_one(user)
    return {"message": "Account created. Waiting for admin approval.", "user_id": str(result.inserted_id)}


@app.post("/auth/login")
async def login(payload: LoginRequest):
    if not payload.email or not payload.password:
        raise HTTPException(400, detail="Email and password are required")

    user = users_col.find_one({"email": payload.email.lower().strip()})
    if not user or not verify_password(payload.password, user["password"]):
        raise HTTPException(401, detail="Invalid email or password")
    if user.get("status") == "banned":
        raise HTTPException(403, detail="Account has been banned")
    if user.get("status") == "suspended":
        raise HTTPException(403, detail="Account is suspended. Contact an admin.")

    users_col.update_one({"_id": user["_id"]}, {"$set": {"last_active": datetime.utcnow()}})
    token = create_token(str(user["_id"]), user["role"])
    return {
        "token": token,
        "user": {
            "id":     str(user["_id"]),
            "name":   user["name"],
            "email":  user["email"],
            "role":   user["role"],
            "status": user["status"],
        }
    }


@app.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return {
        "id":              str(user["_id"]),
        "name":            user["name"],
        "email":           user["email"],
        "role":            user["role"],
        "status":          user["status"],
        "emails_verified": user.get("emails_verified", 0),
        "last_active":     user.get("last_active"),
    }


# ── Admin: Users ──────────────────────────────────────────────────────────────

@app.get("/admin/users")
async def get_users(admin=Depends(require_admin)):
    users = list(users_col.find({}, {"password": 0}))
    for u in users:
        u["id"] = str(u.pop("_id"))
        if u.get("created_at"): u["created_at"] = u["created_at"].isoformat()
        if u.get("last_active"): u["last_active"] = u["last_active"].isoformat()
    return users


@app.put("/admin/users/{user_id}/status")
async def update_user_status(user_id: str, payload: dict, admin=Depends(require_admin)):
    new_status = payload.get("status")
    if new_status not in ["approved", "suspended", "banned", "pending"]:
        raise HTTPException(400, detail="Invalid status")
    try:
        target = users_col.find_one({"_id": ObjectId(user_id)})
    except Exception:
        raise HTTPException(400, detail="Invalid user ID")
    if not target:
        raise HTTPException(404, detail="User not found")
    if target.get("role") == "main_admin":
        raise HTTPException(403, detail="Cannot modify main admin")
    users_col.update_one({"_id": ObjectId(user_id)}, {"$set": {"status": new_status}})
    return {"message": f"User status updated to {new_status}"}


@app.put("/admin/users/{user_id}/role")
async def update_user_role(user_id: str, payload: dict, admin=Depends(require_admin)):
    if admin.get("role") != "main_admin":
        raise HTTPException(403, detail="Only main admin can change roles")
    new_role = payload.get("role")
    if new_role not in ["user", "admin"]:
        raise HTTPException(400, detail="Invalid role")
    try:
        target = users_col.find_one({"_id": ObjectId(user_id)})
    except Exception:
        raise HTTPException(400, detail="Invalid user ID")
    if not target:
        raise HTTPException(404, detail="User not found")
    if target.get("role") == "main_admin":
        raise HTTPException(403, detail="Cannot modify main admin role")
    users_col.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": new_role}})
    return {"message": f"Role updated to {new_role}"}


# ── Verify: Single ────────────────────────────────────────────────────────────

class SingleEmailRequest(BaseModel):
    email: str


@app.post("/verify/single")
async def verify_single(payload: SingleEmailRequest, user=Depends(require_approved)):
    raw   = payload.email.strip()
    EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    parts = re.split(r"[;:|]+", raw)
    parts = [p.strip().lower() for p in parts if EMAIL_RE.search(p.strip())]

    if len(parts) > 1:
        results = [verifier.verify(e) for e in parts]
        log_verification(user, len(parts), "single_multi")
        return {"multiple": True, "results": results}

    result = verifier.verify(raw)
    log_verification(user, 1, "single")
    return result


# ── Verify: Bulk ──────────────────────────────────────────────────────────────

@app.post("/verify/bulk")
async def verify_bulk(background_tasks: BackgroundTasks, file: UploadFile = File(...), user=Depends(require_approved)):
    if not file.filename.endswith(".csv"):
        raise HTTPException(400, detail="Only .csv files are accepted")

    contents = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(contents))
    except Exception:
        raise HTTPException(400, detail="Could not parse CSV.")

    EMAIL_RE     = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    HEADER_RE    = re.compile(r"mail|email|gmail|contact|recipient|address|receiver", re.IGNORECASE)

    # Smart column detection
    target_col = None
    for col in df.columns:
        if HEADER_RE.search(str(col)):
            target_col = col
            break
    if target_col is None:
        best_col, best_count = df.columns[0], 0
        for col in df.columns:
            count = df[col].dropna().astype(str).apply(lambda x: bool(EMAIL_RE.search(x))).sum()
            if count > best_count:
                best_count, best_col = count, col
        target_col = best_col

    all_values = df[target_col].dropna().astype(str).tolist()
    for col in df.columns:
        if col != target_col:
            for val in df[col].dropna().astype(str):
                if EMAIL_RE.search(val):
                    all_values.append(val)

    emails = []
    for entry in all_values:
        found = EMAIL_RE.findall(entry)
        emails.extend([e.lower().strip() for e in found])

    seen  = set()
    emails = [e for e in emails if not (e in seen or seen.add(e))]

    if not emails:
        raise HTTPException(400, detail="No emails found in CSV")
    if len(emails) > 50000:
        raise HTTPException(400, detail="Max 50,000 emails per job")

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "status":   "processing",
        "progress": 0,
        "total":    len(emails),
        "results":  [],
        "user_id":  str(user["_id"]),
        "started_at": time.time(),
    }
    background_tasks.add_task(run_bulk_job, job_id, emails, user)
    return {"job_id": job_id, "total": len(emails)}


def run_bulk_job(job_id: str, emails: list, user):
    results = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(verifier.verify, email): email for email in emails}
        for i, future in enumerate(as_completed(futures), 1):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                results.append({
                    "email": futures[future], "error": str(e),
                    "risk": "HIGH", "category": "bounce", "sendable": False,
                    "smtp_valid": False, "mx_valid": False, "format_valid": True,
                    "catch_all": False, "disposable": False, "message": str(e)
                })
            jobs[job_id]["progress"] = i
            jobs[job_id]["results"]  = results

    jobs[job_id]["status"]       = "done"
    jobs[job_id]["completed_at"] = time.time()

    # Log to verify_logs
    log_verification(user, len(emails), "bulk")


@app.get("/results/{job_id}")
async def get_results(job_id: str, user=Depends(require_approved)):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, detail="Job not found — it may have expired if the server restarted")
    pct = round((job["progress"] / job["total"]) * 100) if job["total"] > 0 else 0
    return {
        "job_id":   job_id,
        "status":   job["status"],
        "progress": job["progress"],
        "total":    job["total"],
        "percent":  pct,
        "results":  job["results"] if job["status"] == "done" else [],
    }


@app.get("/results/{job_id}/export")
async def export_results(job_id: str, category: str = "all", user=Depends(require_approved)):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, detail="Job not found")
    if job["status"] != "done":
        raise HTTPException(400, detail="Job still processing")

    results = job["results"]
    if category == "delivers":
        filtered = [r for r in results if r.get("category") == "delivers"]
    elif category == "unknown":
        filtered = [r for r in results if r.get("category") == "unknown"]
    elif category == "bounce":
        filtered = [r for r in results if r.get("category") == "bounce"]
    else:
        filtered = results

    emails_only = [r["email"] for r in filtered if r.get("email")]
    output = io.StringIO()
    output.write("email\n")
    output.write("\n".join(emails_only))
    output.seek(0)

    filename = f"mailclean_{category}_{job_id[:8]}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── Scout logging ─────────────────────────────────────────────────────────────

class ScoutLogRequest(BaseModel):
    batch_number:  int
    email_count:   int
    subject:       str
    total_batches: int


@app.post("/scout/log")
async def log_scout(payload: ScoutLogRequest, user=Depends(require_approved)):
    db["scout_logs"].insert_one({
        "user_id":      str(user["_id"]),
        "user_name":    user["name"],
        "user_email":   user["email"],
        "batch_number": payload.batch_number,
        "email_count":  payload.email_count,
        "subject":      payload.subject,
        "total_batches": payload.total_batches,
        "sent_at":      datetime.utcnow(),
    })
    inc_op = {"$inc": {"batches_sent": 1, "emails_scouted": payload.email_count}}
    users_col.update_one({"_id": user["_id"]}, inc_op)
    return {"message": "Logged"}


@app.get("/admin/scout-logs")
async def get_scout_logs(admin=Depends(require_admin)):
    logs = list(db["scout_logs"].find({}, {"_id": 0}).sort("sent_at", -1).limit(200))
    for l in logs:
        if l.get("sent_at"): l["sent_at"] = l["sent_at"].isoformat()
    return logs


# ── Open tracking pixel ───────────────────────────────────────────────────────

@app.get("/pixel/{track_id}")
async def track_open(track_id: str, request: Request):
    from fastapi.responses import Response
    import base64
    db["open_events"].insert_one({
        "track_id":  track_id,
        "opened_at": datetime.utcnow(),
        "ip":        request.client.host if request.client else "unknown",
    })
    db["batch_tracks"].update_one(
        {"track_id": track_id},
        {"$inc": {"open_count": 1}, "$set": {"last_opened": datetime.utcnow()}},
    )
    gif = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
    return Response(content=gif, media_type="image/gif", headers={
        "Cache-Control": "no-cache, no-store, must-revalidate, private",
        "Pragma": "no-cache", "Expires": "0",
    })


@app.post("/scout/create-track")
async def create_track(payload: dict, user=Depends(require_approved)):
    import secrets
    track_id  = secrets.token_urlsafe(16)
    pixel_url = f"https://api.brainboxecomlab.com/pixel/{track_id}"
    db["batch_tracks"].insert_one({
        "track_id":     track_id,
        "user_id":      str(user["_id"]),
        "user_name":    user["name"],
        "batch_number": payload.get("batch_number"),
        "total_batches": payload.get("total_batches"),
        "subject":      payload.get("subject"),
        "email_count":  payload.get("email_count"),
        "open_count":   0,
        "last_opened":  None,
        "created_at":   datetime.utcnow(),
    })
    return {
        "track_id":   track_id,
        "pixel_url":  pixel_url,
        "pixel_html": f'<img src="{pixel_url}" width="1" height="1" style="opacity:0;position:absolute;" alt="">',
    }


@app.get("/scout/tracks")
async def get_my_tracks(user=Depends(require_approved)):
    tracks = list(db["batch_tracks"].find(
        {"user_id": str(user["_id"])}, {"_id": 0}
    ).sort("created_at", -1).limit(50))
    for t in tracks:
        if t.get("created_at"): t["created_at"] = t["created_at"].isoformat()
        if t.get("last_opened"): t["last_opened"] = t["last_opened"].isoformat()
    return tracks


@app.get("/admin/tracks")
async def get_all_tracks(admin=Depends(require_admin)):
    tracks = list(db["batch_tracks"].find({}, {"_id": 0}).sort("created_at", -1).limit(100))
    for t in tracks:
        if t.get("created_at"): t["created_at"] = t["created_at"].isoformat()
        if t.get("last_opened"): t["last_opened"] = t["last_opened"].isoformat()
    return tracks


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0.0"}
