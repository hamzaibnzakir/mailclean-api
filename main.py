from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Depends, Header, Request
from routes_dashboard import router as dashboard_router
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, EmailStr
from verifier import EmailVerifier
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import MAX_THREADS
from auth import (
    users_col, hash_password, verify_password, create_token,
    get_current_user, require_approved, require_admin, seed_main_admin
)
from bson import ObjectId
from datetime import datetime
from typing import Optional
import pandas as pd
import uuid
import io
import time
import re

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
jobs = {}
app.include_router(dashboard_router)


@app.on_event("startup")
async def startup():
    seed_main_admin()


# ─── Auth ─────────────────────────────────────────────────────────────────────

class SignupRequest(BaseModel):
    name: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/auth/signup")
async def signup(payload: SignupRequest):
    existing = users_col.find_one({"email": payload.email.lower().strip()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    if len(payload.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    user = {
        "email": payload.email.lower().strip(),
        "password": hash_password(payload.password),
        "name": payload.name.strip(),
        "role": "user",
        "status": "pending",  # pending | approved | suspended | banned
        "created_at": datetime.utcnow(),
        "emails_verified": 0,
        "last_active": None,
    }
    result = users_col.insert_one(user)
    return {"message": "Account created. Waiting for admin approval.", "user_id": str(result.inserted_id)}


@app.post("/auth/login")
async def login(payload: LoginRequest):
    user = users_col.find_one({"email": payload.email.lower().strip()})
    if not user or not verify_password(payload.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if user.get("status") == "banned":
        raise HTTPException(status_code=403, detail="Account has been banned")
    if user.get("status") == "suspended":
        raise HTTPException(status_code=403, detail="Account is suspended")

    # Update last active
    users_col.update_one({"_id": user["_id"]}, {"$set": {"last_active": datetime.utcnow()}})

    token = create_token(str(user["_id"]), user["role"])
    return {
        "token": token,
        "user": {
            "id": str(user["_id"]),
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "status": user["status"],
        }
    }


@app.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return {
        "id": str(user["_id"]),
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "status": user["status"],
        "emails_verified": user.get("emails_verified", 0),
        "last_active": user.get("last_active"),
    }


# ─── Admin ────────────────────────────────────────────────────────────────────

@app.get("/admin/users")
async def get_users(admin=Depends(require_admin)):
    users = list(users_col.find({}, {"password": 0}))
    for u in users:
        u["id"] = str(u.pop("_id"))
        if u.get("created_at"):
            u["created_at"] = u["created_at"].isoformat()
        if u.get("last_active"):
            u["last_active"] = u["last_active"].isoformat()
    return users


@app.put("/admin/users/{user_id}/status")
async def update_user_status(user_id: str, payload: dict, admin=Depends(require_admin)):
    new_status = payload.get("status")
    if new_status not in ["approved", "suspended", "banned", "pending"]:
        raise HTTPException(status_code=400, detail="Invalid status")

    target = users_col.find_one({"_id": ObjectId(user_id)})
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    # Protect main admin
    if target.get("role") == "main_admin":
        raise HTTPException(status_code=403, detail="Cannot modify main admin")

    users_col.update_one({"_id": ObjectId(user_id)}, {"$set": {"status": new_status}})
    return {"message": f"User status updated to {new_status}"}


@app.put("/admin/users/{user_id}/role")
async def update_user_role(user_id: str, payload: dict, admin=Depends(require_admin)):
    # Only main admin can promote to admin
    if admin.get("role") != "main_admin":
        raise HTTPException(status_code=403, detail="Only main admin can change roles")

    new_role = payload.get("role")
    if new_role not in ["user", "admin"]:
        raise HTTPException(status_code=400, detail="Invalid role")

    target = users_col.find_one({"_id": ObjectId(user_id)})
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.get("role") == "main_admin":
        raise HTTPException(status_code=403, detail="Cannot modify main admin role")

    users_col.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": new_role}})
    return {"message": f"User role updated to {new_role}"}


# ─── Verify (protected) ───────────────────────────────────────────────────────

class SingleEmailRequest(BaseModel):
    email: str


@app.post("/verify/single")
async def verify_single(payload: SingleEmailRequest, user=Depends(require_approved)):
    raw = payload.email.strip()
    parts = re.split(r"[;:|]+", raw)
    parts = [p.strip().lower() for p in parts if "@" in p.strip() and "." in p.strip().split("@")[-1]]

    if len(parts) > 1:
        results = [verifier.verify(e) for e in parts]
        users_col.update_one({"_id": user["_id"]}, {"$inc": {"emails_verified": len(parts)}})
        return {"multiple": True, "results": results}

    result = verifier.verify(raw)
    users_col.update_one({"_id": user["_id"]}, {"$inc": {"emails_verified": 1}})
    return result


@app.post("/verify/bulk")
async def verify_bulk(background_tasks: BackgroundTasks, file: UploadFile = File(...), user=Depends(require_approved)):
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are accepted")
    contents = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(contents))
        raw = df.iloc[:, 0].dropna().tolist()
    except Exception:
        raise HTTPException(status_code=400, detail="Could not parse CSV.")

    emails = []
    for entry in raw:
        entry = str(entry).strip()
        parts = re.split(r"[;:|\s]+", entry)
        for part in parts:
            part = part.strip().lower()
            if "@" in part and "." in part.split("@")[-1]:
                emails.append(part)

    seen = set()
    emails = [e for e in emails if not (e in seen or seen.add(e))]

    if not emails:
        raise HTTPException(status_code=400, detail="No emails found in CSV")
    if len(emails) > 50000:
        raise HTTPException(status_code=400, detail="Max 50,000 emails per job")

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "status": "processing", "progress": 0, "total": len(emails),
        "results": [], "started_at": time.time(), "user_id": str(user["_id"])
    }
    background_tasks.add_task(run_bulk_job, job_id, emails, str(user["_id"]))
    return {"job_id": job_id, "total": len(emails)}


def run_bulk_job(job_id: str, emails: list, user_id: str):
    results = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(verifier.verify, email): email for email in emails}
        for i, future in enumerate(as_completed(futures), 1):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                results.append({"email": futures[future], "error": str(e), "risk": "HIGH", "category": "bounce", "sendable": False})
            jobs[job_id]["progress"] = i
            jobs[job_id]["results"] = results
    jobs[job_id]["status"] = "done"
    jobs[job_id]["completed_at"] = time.time()
    users_col.update_one({"_id": ObjectId(user_id)}, {"$inc": {"emails_verified": len(emails)}})
    from auth import db
    user_doc = users_col.find_one({"_id": ObjectId(user_id)})
    db["verify_logs"].insert_one({"user_id": user_id, "user_name": user_doc.get("name","") if user_doc else "", "user_email": user_doc.get("email","") if user_doc else "", "email_count": len(emails), "sent_at": datetime.utcnow()})


@app.get("/results/{job_id}")
async def get_results(job_id: str, user=Depends(require_approved)):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    pct = round((job["progress"] / job["total"]) * 100) if job["total"] > 0 else 0
    return {
        "job_id": job_id, "status": job["status"],
        "progress": job["progress"], "total": job["total"],
        "percent": pct, "results": job["results"] if job["status"] == "done" else []
    }


@app.get("/results/{job_id}/export")
async def export_results(job_id: str, category: str = "all", user=Depends(require_approved)):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job["status"] != "done":
        raise HTTPException(status_code=400, detail="Job still processing")

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


# ─── Scout logging ───────────────────────────────────────────────────────────

class ScoutLogRequest(BaseModel):
    batch_number: int
    email_count: int
    subject: str
    total_batches: int

@app.post("/scout/log")
async def log_scout(payload: ScoutLogRequest, user=Depends(require_approved)):
    from auth import db
    db["scout_logs"].insert_one({
        "user_id": str(user["_id"]),
        "user_name": user["name"],
        "user_email": user["email"],
        "batch_number": payload.batch_number,
        "email_count": payload.email_count,
        "subject": payload.subject,
        "total_batches": payload.total_batches,
        "sent_at": datetime.utcnow(),
    })
    # Update user scout count
    inc_op = {"$inc": {"batches_sent": 1, "emails_scouted": payload.email_count}}
    users_col.update_one({"_id": user["_id"]}, inc_op)
    return {"message": "Logged"}


@app.get("/admin/scout-logs")
async def get_scout_logs(admin=Depends(require_admin)):
    from auth import db
    logs = list(db["scout_logs"].find({}, {"_id": 0}).sort("sent_at", -1).limit(200))
    for l in logs:
        if l.get("sent_at"):
            l["sent_at"] = l["sent_at"].isoformat()
    return logs


# ─── Email open tracking ──────────────────────────────────────────────────────

@app.get("/track/open/{track_id}")
async def track_open(track_id: str, request: Request):
    from auth import db
    from fastapi import Request
    db["open_events"].insert_one({
        "track_id": track_id,
        "opened_at": datetime.utcnow(),
        "ip": request.client.host if request.client else "unknown",
    })
    db["batch_tracks"].update_one(
        {"track_id": track_id},
        {"$inc": {"open_count": 1}, "$set": {"last_opened": datetime.utcnow()}},
    )
    # Return 1x1 transparent GIF
    import base64
    gif = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
    from fastapi.responses import Response
    return Response(content=gif, media_type="image/gif", headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
    })


@app.post("/scout/create-track")
async def create_track(payload: dict, user=Depends(require_approved)):
    from auth import db
    import secrets
    track_id = secrets.token_urlsafe(16)
    db["batch_tracks"].insert_one({
        "track_id": track_id,
        "user_id": str(user["_id"]),
        "user_name": user["name"],
        "batch_number": payload.get("batch_number"),
        "total_batches": payload.get("total_batches"),
        "subject": payload.get("subject"),
        "email_count": payload.get("email_count"),
        "open_count": 0,
        "last_opened": None,
        "created_at": datetime.utcnow(),
    })
    pixel_url = f"https://api.brainboxecomlab.com/track/open/{track_id}"
    pixel_html = f'<img src="{pixel_url}" width="1" height="1" style="display:none" alt="" />'
    return {"track_id": track_id, "pixel_url": pixel_url, "pixel_html": pixel_html}


@app.get("/scout/tracks")
async def get_my_tracks(user=Depends(require_approved)):
    from auth import db
    tracks = list(db["batch_tracks"].find(
        {"user_id": str(user["_id"])}, {"_id": 0}
    ).sort("created_at", -1).limit(50))
    for t in tracks:
        if t.get("created_at"): t["created_at"] = t["created_at"].isoformat()
        if t.get("last_opened"): t["last_opened"] = t["last_opened"].isoformat()
    return tracks


@app.get("/admin/tracks")
async def get_all_tracks(admin=Depends(require_admin)):
    from auth import db
    tracks = list(db["batch_tracks"].find({}, {"_id": 0}).sort("created_at", -1).limit(100))
    for t in tracks:
        if t.get("created_at"): t["created_at"] = t["created_at"].isoformat()
        if t.get("last_opened"): t["last_opened"] = t["last_opened"].isoformat()
    return tracks


@app.get("/health")
async def health():
    return {"status": "ok"}
