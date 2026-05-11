from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from verifier import EmailVerifier
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import MAX_THREADS
import pandas as pd
import uuid
import io
import time

app = FastAPI(title="MailClean API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

verifier = EmailVerifier()
jobs = {}


class SingleEmailRequest(BaseModel):
    email: str


# ─── Single verify ────────────────────────────────────────────────────────────

@app.post("/verify/single")
async def verify_single(payload: SingleEmailRequest):
    result = verifier.verify(payload.email)
    return result


# ─── Bulk verify ──────────────────────────────────────────────────────────────

@app.post("/verify/bulk")
async def verify_bulk(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are accepted")

    contents = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(contents))
        emails = df.iloc[:, 0].dropna().tolist()
    except Exception:
        raise HTTPException(status_code=400, detail="Could not parse CSV. Make sure emails are in the first column.")

    if len(emails) == 0:
        raise HTTPException(status_code=400, detail="No emails found in CSV")

    if len(emails) > 50000:
        raise HTTPException(status_code=400, detail="Max 50,000 emails per job")

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "status": "processing",
        "progress": 0,
        "total": len(emails),
        "results": [],
        "started_at": time.time(),
    }

    background_tasks.add_task(run_bulk_job, job_id, emails)

    return {"job_id": job_id, "total": len(emails)}


def run_bulk_job(job_id: str, emails: list):
    results = []
    total = len(emails)

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(verifier.verify, email): email for email in emails}
        for i, future in enumerate(as_completed(futures), 1):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                results.append({"email": futures[future], "error": str(e), "risk": "HIGH"})

            jobs[job_id]["progress"] = i
            jobs[job_id]["results"] = results

    jobs[job_id]["status"] = "done"
    jobs[job_id]["completed_at"] = time.time()


# ─── Job status ───────────────────────────────────────────────────────────────

@app.get("/results/{job_id}")
async def get_results(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    pct = round((job["progress"] / job["total"]) * 100) if job["total"] > 0 else 0

    return {
        "job_id": job_id,
        "status": job["status"],
        "progress": job["progress"],
        "total": job["total"],
        "percent": pct,
        "results": job["results"] if job["status"] == "done" else [],
    }


# ─── CSV export ───────────────────────────────────────────────────────────────

@app.get("/results/{job_id}/export")
async def export_results(job_id: str, category: str = "all"):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job["status"] != "done":
        raise HTTPException(status_code=400, detail="Job still processing")

    df = pd.DataFrame(job["results"])

    if category == "delivers":
        df = df[df["category"] == "delivers"]
    elif category == "unknown":
        df = df[df["category"] == "unknown"]
    elif category == "bounce":
        df = df[df["category"] == "bounce"]

    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)

    filename = f"mailclean_{category}_{job_id[:8]}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ─── Health check ─────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok"}
