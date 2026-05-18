from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.responses import StreamingResponse
from auth import require_approved, require_admin, db, users_col
from verifier import EmailVerifier
from pydantic import BaseModel
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import MAX_THREADS
from datetime import datetime, timedelta
from bson import ObjectId
from typing import Optional
import pandas as pd
import re
import io
import uuid

router = APIRouter()
verifier = EmailVerifier()

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

COUNTRY_META = {
    "US": {"name": "United States", "flag": "🇺🇸"},
    "GB": {"name": "United Kingdom", "flag": "🇬🇧"},
    "CA": {"name": "Canada",         "flag": "🇨🇦"},
    "AU": {"name": "Australia",      "flag": "🇦🇺"},
}

leads_col  = db["leads"]
lead_jobs_col = db["lead_jobs"]  # Persist jobs to MongoDB

# Indexes
try:
    leads_col.create_index([("email", 1), ("country", 1)], unique=True)
    leads_col.create_index("status")
    leads_col.create_index("country")
    leads_col.create_index("claimed_at")
    lead_jobs_col.create_index("user_id")
    lead_jobs_col.create_index("status")
    lead_jobs_col.create_index("created_at")
except Exception:
    pass

MAX_CLAIM_PER_USER_PER_DAY = 3000  # Daily limit per user


def get_meta(country: str) -> dict:
    return COUNTRY_META.get(country, {"name": country, "flag": "🌍"})


# ── Expire abandoned jobs ─────────────────────────────────────────────────────
def expire_abandoned_jobs():
    """Return claimed emails to pool if job abandoned for >45 minutes."""
    cutoff = datetime.utcnow() - timedelta(minutes=45)
    abandoned = list(lead_jobs_col.find({
        "status": "processing",
        "created_at": {"$lt": cutoff}
    }))
    for job in abandoned:
        leads_col.update_many(
            {"claimed_by_job": str(job["_id"]), "verified_result": None},
            {"$set": {
                "status": "available",
                "claimed_by": None,
                "claimed_by_job": None,
                "claimed_at": None,
            }}
        )
        lead_jobs_col.update_one(
            {"_id": job["_id"]},
            {"$set": {"status": "expired"}}
        )


# ── Admin: Upload leads CSV ───────────────────────────────────────────────────
@router.post("/admin/leads/upload/{country}")
async def upload_leads(country: str, file: UploadFile = File(...), admin=Depends(require_admin)):
    country = country.upper().strip()
    if not country or len(country) > 10:
        raise HTTPException(400, detail="Invalid country code")
    if not file.filename.endswith(".csv"):
        raise HTTPException(400, detail="Only .csv files accepted")

    contents = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(contents))
    except Exception:
        raise HTTPException(400, detail="Could not parse CSV")

    # Smart email column detection
    email_col = None
    for col in df.columns:
        if re.search(r"mail|email|gmail|contact|recipient", col, re.IGNORECASE):
            email_col = col
            break
    if email_col is None:
        email_col = df.columns[0]

    domain_col = None
    for col in df.columns:
        if re.search(r"domain|url|website|store", col, re.IGNORECASE):
            domain_col = col
            break

    inserted = 0
    skipped  = 0
    for _, row in df.iterrows():
        cell   = str(row.get(email_col, "") or "")
        emails = [e.lower().strip() for e in EMAIL_RE.findall(cell)]
        domain = str(row.get(domain_col, "") or "") if domain_col else ""
        if domain == "nan": domain = ""

        for email in emails:
            if not email or "@" not in email:
                continue
            try:
                leads_col.insert_one({
                    "email": email,
                    "country": country,
                    "domain": domain,
                    "status": "available",
                    "claimed_by": None,
                    "claimed_by_job": None,
                    "claimed_at": None,
                    "verified_result": None,
                    "uploaded_at": datetime.utcnow(),
                })
                inserted += 1
            except Exception:
                skipped += 1

    return {
        "message": "Upload complete",
        "country": country,
        "inserted": inserted,
        "skipped_duplicates": skipped,
        "total_processed": inserted + skipped,
    }


# ── Admin: Stats ──────────────────────────────────────────────────────────────
@router.get("/admin/leads/stats")
async def leads_stats(admin=Depends(require_admin)):
    expire_abandoned_jobs()
    countries = leads_col.distinct("country")
    stats = []
    for country in sorted(countries):
        total     = leads_col.count_documents({"country": country})
        available = leads_col.count_documents({"country": country, "status": "available"})
        claimed   = leads_col.count_documents({"country": country, "status": "claimed"})
        expired   = leads_col.count_documents({"country": country, "status": "expired"})
        meta      = get_meta(country)
        stats.append({
            "country": country,
            "name": meta["name"],
            "flag": meta["flag"],
            "total": total,
            "available": available,
            "claimed": claimed,
            "expired": expired,
        })
    return stats


@router.delete("/admin/leads/delete/{country}")
async def delete_country_leads(country: str, admin=Depends(require_admin)):
    country = country.upper()
    result = leads_col.delete_many({"country": country})
    return {"deleted": result.deleted_count, "country": country}


@router.delete("/admin/leads/delete-available/{country}")
async def delete_available_leads(country: str, admin=Depends(require_admin)):
    country = country.upper()
    result = leads_col.delete_many({"country": country, "status": "available"})
    return {"deleted": result.deleted_count, "country": country}


@router.get("/admin/leads/sample/{country}")
async def get_sample_leads(country: str, admin=Depends(require_admin)):
    country = country.upper()
    docs = list(leads_col.find(
        {"country": country}, {"_id": 0, "email": 1, "domain": 1, "status": 1}
    ).limit(10))
    return docs


@router.get("/admin/leads/jobs")
async def get_all_lead_jobs(admin=Depends(require_admin)):
    jobs = list(lead_jobs_col.find({}, {"results": 0}).sort("created_at", -1).limit(100))
    for j in jobs:
        j["id"] = str(j.pop("_id"))
        if j.get("created_at"): j["created_at"] = j["created_at"].isoformat()
        if j.get("completed_at"): j["completed_at"] = j["completed_at"].isoformat()
    return jobs


# ── User: Country overview ────────────────────────────────────────────────────
@router.get("/leads/countries")
async def get_countries(user=Depends(require_approved)):
    countries_list = leads_col.distinct("country")
    countries = []
    for country in countries_list:
        available = leads_col.count_documents({"country": country, "status": "available"})
        if available > 0:
            meta = get_meta(country)
            countries.append({
                "country": country,
                "name": meta["name"],
                "flag": meta["flag"],
                "available": available,
            })
    return sorted(countries, key=lambda x: x["available"], reverse=True)


# ── User: Claim + verify ──────────────────────────────────────────────────────
class ClaimRequest(BaseModel):
    country: str
    amount: int


@router.post("/leads/claim-and-verify")
async def claim_and_verify(
    payload: ClaimRequest,
    background_tasks: BackgroundTasks,
    user=Depends(require_approved)
):
    expire_abandoned_jobs()

    country = payload.country.upper().strip()
    if not country:
        raise HTTPException(400, detail="Invalid country")
    if payload.amount < 100 or payload.amount > 2000:
        raise HTTPException(400, detail="Amount must be between 100 and 2000")

    user_id = str(user["_id"])

    # Daily rate limit
    day_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    claimed_today = leads_col.count_documents({
        "claimed_by": user_id,
        "claimed_at": {"$gte": day_start}
    })
    if claimed_today + payload.amount > MAX_CLAIM_PER_USER_PER_DAY:
        remaining = max(0, MAX_CLAIM_PER_USER_PER_DAY - claimed_today)
        raise HTTPException(429, detail=f"Daily limit reached. You can claim {remaining} more today.")

    # Check for existing active job for this user
    active = lead_jobs_col.find_one({"user_id": user_id, "status": "processing"})
    if active:
        raise HTTPException(400, detail=f"You have a job already running. Wait for it to complete or check your history.")

    # Create job document first
    job_doc = {
        "user_id": user_id,
        "user_name": user["name"],
        "user_email": user["email"],
        "country": country,
        "amount": payload.amount,
        "status": "processing",
        "progress": 0,
        "total": 0,
        "results": [],
        "created_at": datetime.utcnow(),
        "completed_at": None,
    }
    job_result = lead_jobs_col.insert_one(job_doc)
    job_id = str(job_result.inserted_id)

    # Atomically claim emails
    claimed_emails = []
    claimed_at = datetime.utcnow()

    cursor = leads_col.find(
        {"country": country, "status": "available"},
        {"_id": 1, "email": 1}
    ).limit(payload.amount)

    for doc in cursor:
        result = leads_col.find_one_and_update(
            {"_id": doc["_id"], "status": "available"},
            {"$set": {
                "status": "claimed",
                "claimed_by": user_id,
                "claimed_by_job": job_id,
                "claimed_at": claimed_at,
            }},
            return_document=True
        )
        if result:
            claimed_emails.append(result["email"])

    if not claimed_emails:
        lead_jobs_col.update_one({"_id": job_result.inserted_id}, {"$set": {"status": "failed", "error": "No available leads"}})
        raise HTTPException(404, detail=f"No available leads for {country}. Admin needs to upload more.")

    # Update job with actual count
    lead_jobs_col.update_one(
        {"_id": job_result.inserted_id},
        {"$set": {"total": len(claimed_emails)}}
    )

    background_tasks.add_task(run_lead_verification, job_id, claimed_emails, user_id, user["name"], user["email"])
    return {"job_id": job_id, "claimed": len(claimed_emails), "country": country}


def run_lead_verification(job_id: str, emails: list, user_id: str, user_name: str, user_email: str):
    results = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(verifier.verify, email): email for email in emails}
        for i, future in enumerate(as_completed(futures), 1):
            email = futures[future]
            try:
                result = future.result()
                results.append(result)
                leads_col.update_one(
                    {"email": email, "claimed_by": user_id},
                    {"$set": {"verified_result": result, "verified_at": datetime.utcnow()}}
                )
            except Exception as e:
                results.append({
                    "email": email, "error": str(e),
                    "category": "bounce", "risk": "HIGH", "sendable": False,
                    "smtp_valid": False, "mx_valid": False, "format_valid": True,
                    "catch_all": False, "disposable": False, "message": str(e)
                })

            # Update progress in MongoDB
            lead_jobs_col.update_one(
                {"_id": ObjectId(job_id)},
                {"$set": {"progress": i, "results": results}}
            )

    # Mark done
    lead_jobs_col.update_one(
        {"_id": ObjectId(job_id)},
        {"$set": {"status": "done", "completed_at": datetime.utcnow(), "results": results}}
    )

    # Log to verify_logs for dashboard stats
    db["verify_logs"].insert_one({
        "user_id":    user_id,
        "user_name":  user_name,
        "user_email": user_email,
        "email_count": len(emails),
        "source": "scout_leads",
        "sent_at": datetime.utcnow(),
    })
    inc_op = {"$inc": {"emails_verified": len(emails)}}
    users_col.update_one({"_id": ObjectId(user_id)}, inc_op)


# ── Job status (resumable) ────────────────────────────────────────────────────
@router.get("/leads/status/{job_id}")
async def lead_job_status(job_id: str, user=Depends(require_approved)):
    try:
        job = lead_jobs_col.find_one({"_id": ObjectId(job_id)})
    except Exception:
        raise HTTPException(400, detail="Invalid job ID")
    if not job:
        raise HTTPException(404, detail="Job not found")
    if job["user_id"] != str(user["_id"]):
        raise HTTPException(403, detail="Not your job")

    pct = round((job["progress"] / job["total"]) * 100) if job.get("total", 0) > 0 else 0
    return {
        "job_id": job_id,
        "status": job["status"],
        "progress": job.get("progress", 0),
        "total": job.get("total", 0),
        "percent": pct,
        "country": job.get("country", ""),
        "results": job.get("results", []) if job["status"] == "done" else [],
    }


# ── User: Job history ─────────────────────────────────────────────────────────
@router.get("/leads/history")
async def my_lead_history(user=Depends(require_approved)):
    jobs = list(lead_jobs_col.find(
        {"user_id": str(user["_id"])},
        {"results": 0}
    ).sort("created_at", -1).limit(20))
    for j in jobs:
        j["id"] = str(j.pop("_id"))
        if j.get("created_at"): j["created_at"] = j["created_at"].isoformat()
        if j.get("completed_at"): j["completed_at"] = j["completed_at"].isoformat()
    return jobs


# ── Resume: get results of a past done job ────────────────────────────────────
@router.get("/leads/results/{job_id}")
async def get_lead_results(job_id: str, user=Depends(require_approved)):
    try:
        job = lead_jobs_col.find_one({"_id": ObjectId(job_id)})
    except Exception:
        raise HTTPException(400, detail="Invalid job ID")
    if not job:
        raise HTTPException(404, detail="Job not found")
    if job["user_id"] != str(user["_id"]):
        raise HTTPException(403, detail="Not your job")
    if job["status"] != "done":
        raise HTTPException(400, detail="Job not complete yet")

    pct = round((job["progress"] / job["total"]) * 100) if job.get("total", 0) > 0 else 0
    return {
        "job_id": job_id,
        "status": job["status"],
        "progress": job.get("progress", 0),
        "total": job.get("total", 0),
        "percent": pct,
        "country": job.get("country", ""),
        "results": job.get("results", []),
    }


# ── Export ────────────────────────────────────────────────────────────────────
@router.get("/leads/export/{job_id}")
async def export_lead_emails(job_id: str, category: str = "all", user=Depends(require_approved)):
    try:
        job = lead_jobs_col.find_one({"_id": ObjectId(job_id)})
    except Exception:
        raise HTTPException(400, detail="Invalid job ID")
    if not job:
        raise HTTPException(404, detail="Job not found")
    if job["user_id"] != str(user["_id"]):
        raise HTTPException(403, detail="Not your job")
    if job["status"] != "done":
        raise HTTPException(400, detail="Job still processing")

    results = job.get("results", [])
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

    filename = f"leads_{job.get('country', 'XX')}_{category}_{job_id[:8]}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
