from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.responses import StreamingResponse
from auth import require_approved, require_admin, db
from verifier import EmailVerifier
from pydantic import BaseModel
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import MAX_THREADS
from datetime import datetime
import pandas as pd
import re
import io
import uuid

router = APIRouter()
verifier = EmailVerifier()

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

VALID_COUNTRIES = {"US", "GB", "CA", "AU"}
COUNTRY_NAMES  = {"US": "United States", "GB": "United Kingdom", "CA": "Canada", "AU": "Australia"}
COUNTRY_FLAGS  = {"US": "🇺🇸", "GB": "🇬🇧", "CA": "🇨🇦", "AU": "🇦🇺"}

leads_col = db["leads"]
lead_jobs  = {}

# Indexes — run once
leads_col.create_index([("email", 1), ("country", 1)], unique=True)
leads_col.create_index("status")
leads_col.create_index("country")


def extract_emails_from_cell(cell_value: str) -> list:
    """Extract all emails from a cell — handles colon/semicolon separated."""
    if not cell_value or pd.isna(cell_value):
        return []
    return [e.lower().strip() for e in EMAIL_RE.findall(str(cell_value))]


# ── Admin: Upload leads CSV ───────────────────────────────────────────────────

@router.post("/admin/leads/upload/{country}")
async def upload_leads(country: str, file: UploadFile = File(...), admin=Depends(require_admin)):
    country = country.upper()
    if country not in VALID_COUNTRIES:
        raise HTTPException(400, detail=f"Country must be one of: {', '.join(VALID_COUNTRIES)}")
    if not file.filename.endswith(".csv"):
        raise HTTPException(400, detail="Only .csv files accepted")

    contents = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(contents))
    except Exception:
        raise HTTPException(400, detail="Could not parse CSV")

    # Find email column
    email_col = None
    for col in df.columns:
        if re.search(r"mail|email|gmail|contact|recipient", col, re.IGNORECASE):
            email_col = col
            break
    if email_col is None:
        email_col = df.columns[0]

    # Find domain/store URL column if available
    domain_col = None
    for col in df.columns:
        if re.search(r"domain|url|website|store", col, re.IGNORECASE):
            domain_col = col
            break

    # Extract all emails
    inserted = 0
    skipped  = 0
    docs     = []

    for _, row in df.iterrows():
        cell = row.get(email_col, "")
        emails = extract_emails_from_cell(str(cell))
        domain = str(row.get(domain_col, "")) if domain_col else ""

        for email in emails:
            if not email or "@" not in email:
                continue
            docs.append({
                "email": email,
                "country": country,
                "domain": domain if domain != "nan" else "",
                "status": "available",
                "claimed_by": None,
                "claimed_at": None,
                "verified_result": None,
                "uploaded_at": datetime.utcnow(),
            })

    # Batch insert — skip duplicates
    if docs:
        for doc in docs:
            try:
                leads_col.insert_one(doc)
                inserted += 1
            except Exception:
                skipped += 1  # Duplicate

    return {
        "message": "Upload complete",
        "country": country,
        "inserted": inserted,
        "skipped_duplicates": skipped,
        "total_processed": len(docs),
    }


# ── Admin: Stats ──────────────────────────────────────────────────────────────

@router.get("/admin/leads/stats")
async def leads_stats(admin=Depends(require_admin)):
    stats = []
    for country in VALID_COUNTRIES:
        total     = leads_col.count_documents({"country": country})
        available = leads_col.count_documents({"country": country, "status": "available"})
        claimed   = leads_col.count_documents({"country": country, "status": "claimed"})
        stats.append({
            "country": country,
            "name": COUNTRY_NAMES[country],
            "flag": COUNTRY_FLAGS[country],
            "total": total,
            "available": available,
            "claimed": claimed,
        })
    return stats


# ── User: Country overview ────────────────────────────────────────────────────

@router.get("/leads/countries")
async def get_countries(user=Depends(require_approved)):
    countries = []
    for country in VALID_COUNTRIES:
        available = leads_col.count_documents({"country": country, "status": "available"})
        countries.append({
            "country": country,
            "name": COUNTRY_NAMES[country],
            "flag": COUNTRY_FLAGS[country],
            "available": available,
        })
    return sorted(countries, key=lambda x: x["available"], reverse=True)


# ── User: Claim + verify ──────────────────────────────────────────────────────

class ClaimRequest(BaseModel):
    country: str
    amount: int


@router.post("/leads/claim-and-verify")
async def claim_and_verify(payload: ClaimRequest, background_tasks: BackgroundTasks, user=Depends(require_approved)):
    country = payload.country.upper()
    if country not in VALID_COUNTRIES:
        raise HTTPException(400, detail="Invalid country")
    if payload.amount < 100 or payload.amount > 2000:
        raise HTTPException(400, detail="Amount must be between 100 and 2000")

    # Atomically claim emails — one at a time to avoid race conditions
    claimed_ids = []
    claimed_emails = []
    user_id = str(user["_id"])
    claimed_at = datetime.utcnow()

    cursor = leads_col.find(
        {"country": country, "status": "available"},
        {"_id": 1, "email": 1}
    ).limit(payload.amount)

    for doc in cursor:
        result = leads_col.find_one_and_update(
            {"_id": doc["_id"], "status": "available"},  # Double check still available
            {"$set": {
                "status": "claimed",
                "claimed_by": user_id,
                "claimed_by_name": user["name"],
                "claimed_at": claimed_at,
            }},
            return_document=True
        )
        if result:
            claimed_ids.append(result["_id"])
            claimed_emails.append(result["email"])

    if not claimed_emails:
        raise HTTPException(404, detail=f"No available leads for {country}. Admin needs to upload more.")

    # Create a verification job
    job_id = str(uuid.uuid4())
    lead_jobs[job_id] = {
        "status": "processing",
        "total": len(claimed_emails),
        "progress": 0,
        "results": [],
        "country": country,
        "user_id": user_id,
        "started_at": datetime.utcnow(),
    }

    background_tasks.add_task(run_lead_verification, job_id, claimed_emails, claimed_ids, user_id)
    return {"job_id": job_id, "claimed": len(claimed_emails), "country": country}


def run_lead_verification(job_id: str, emails: list, doc_ids: list, user_id: str):
    results = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(verifier.verify, email): email for email in emails}
        for i, future in enumerate(as_completed(futures), 1):
            try:
                result = future.result()
                results.append(result)
                # Store result back on the lead document
                email = futures[future]
                leads_col.update_one(
                    {"email": email, "claimed_by": user_id},
                    {"$set": {"verified_result": result, "verified_at": datetime.utcnow()}}
                )
            except Exception as e:
                results.append({"email": futures[future], "error": str(e), "category": "bounce", "risk": "HIGH", "sendable": False})
            lead_jobs[job_id]["progress"] = i
            lead_jobs[job_id]["results"] = results

    lead_jobs[job_id]["status"] = "done"
    lead_jobs[job_id]["completed_at"] = datetime.utcnow()


@router.get("/leads/status/{job_id}")
async def lead_job_status(job_id: str, user=Depends(require_approved)):
    job = lead_jobs.get(job_id)
    if not job:
        raise HTTPException(404, detail="Job not found")
    pct = round((job["progress"] / job["total"]) * 100) if job["total"] > 0 else 0
    return {
        "job_id": job_id,
        "status": job["status"],
        "progress": job["progress"],
        "total": job["total"],
        "percent": pct,
        "country": job["country"],
        "results": job["results"] if job["status"] == "done" else [],
    }


@router.get("/leads/export/{job_id}")
async def export_lead_emails(job_id: str, category: str = "all", user=Depends(require_approved)):
    job = lead_jobs.get(job_id)
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

    filename = f"leads_{job['country']}_{category}_{job_id[:8]}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
