from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from auth import require_approved, require_admin, db, users_col
from bson import ObjectId
from datetime import datetime
import os
import time
import math

router = APIRouter()

GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
REDIRECT_URI         = "https://api.brainboxecomlab.com/auth/google/callback"
FRONTEND_URL         = "https://verify.brainboxecomlab.com"

SCOPES = [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.readonly",
    "openid", "email", "profile",
]


def get_google_auth_url(state: str) -> str:
    import urllib.parse
    params = {
        "client_id":     GOOGLE_CLIENT_ID,
        "redirect_uri":  REDIRECT_URI,
        "response_type": "code",
        "scope":         " ".join(SCOPES),
        "access_type":   "offline",
        "prompt":        "consent select_account",
        "state":         state,
    }
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)


async def exchange_code(code: str) -> dict:
    import httpx
    async with httpx.AsyncClient() as client:
        resp = await client.post("https://oauth2.googleapis.com/token", data={
            "code": code, "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI, "grant_type": "authorization_code",
        })
        if resp.status_code != 200:
            raise HTTPException(400, detail=f"Token exchange failed: {resp.text}")
        return resp.json()


async def refresh_access_token(refresh_token: str) -> str:
    import httpx
    async with httpx.AsyncClient() as client:
        resp = await client.post("https://oauth2.googleapis.com/token", data={
            "refresh_token": refresh_token, "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET, "grant_type": "refresh_token",
        })
        data = resp.json()
        if "access_token" not in data:
            raise HTTPException(400, detail="Failed to refresh token")
        return data["access_token"]


async def get_valid_token(user_id: str, gmail_email: str) -> str:
    doc = db["gmail_tokens"].find_one({"user_id": user_id, "gmail_email": gmail_email})
    if not doc:
        raise HTTPException(403, detail=f"{gmail_email} not connected.")
    if doc.get("expires_at", 0) < time.time() + 60:
        new_token = await refresh_access_token(doc["refresh_token"])
        db["gmail_tokens"].update_one(
            {"user_id": user_id, "gmail_email": gmail_email},
            {"$set": {"access_token": new_token, "expires_at": time.time() + 3600}}
        )
        return new_token
    return doc["access_token"]


# ── OAuth ─────────────────────────────────────────────────────────────────────

@router.get("/auth/google/connect")
async def gmail_connect(user=Depends(require_approved)):
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(500, detail="Google OAuth not configured")
    url = get_google_auth_url(str(user["_id"]))
    return {"auth_url": url}


@router.get("/auth/google/callback")
async def gmail_callback(code: str = None, state: str = None, error: str = None):
    if error:
        return RedirectResponse(f"{FRONTEND_URL}/app?gmail_error={error}")
    if not code or not state:
        return RedirectResponse(f"{FRONTEND_URL}/app?gmail_error=missing_params")

    try:
        tokens = await exchange_code(code)
    except Exception:
        return RedirectResponse(f"{FRONTEND_URL}/app?gmail_error=exchange_failed")

    user_id = state
    import httpx
    try:
        async with httpx.AsyncClient() as client:
            profile = await client.get(
                "https://www.googleapis.com/gmail/v1/users/me/profile",
                headers={"Authorization": f"Bearer {tokens['access_token']}"}
            )
            gmail_email = profile.json().get("emailAddress", "")
    except Exception:
        gmail_email = ""

    if not gmail_email:
        return RedirectResponse(f"{FRONTEND_URL}/app?gmail_error=could_not_get_email")

    # Block if connected to another user
    existing = db["gmail_tokens"].find_one({"gmail_email": gmail_email, "user_id": {"$ne": user_id}})
    if existing:
        return RedirectResponse(f"{FRONTEND_URL}/app?gmail_error=account_already_connected")

    db["gmail_tokens"].update_one(
        {"user_id": user_id, "gmail_email": gmail_email},
        {"$set": {
            "user_id": user_id, "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token", ""),
            "expires_at": time.time() + tokens.get("expires_in", 3600),
            "gmail_email": gmail_email, "connected_at": datetime.utcnow(),
            "scopes": SCOPES, "active": True, "send_count": 0,
        }},
        upsert=True
    )
    users_col.update_one(
        {"_id": ObjectId(user_id)},
        {"$addToSet": {"gmail_accounts": gmail_email}}
    )
    import urllib.parse
    return RedirectResponse(f"{FRONTEND_URL}/app?gmail_connected=true&account={urllib.parse.quote(gmail_email)}")


@router.delete("/auth/google/disconnect/{gmail_email:path}")
async def gmail_disconnect(gmail_email: str, user=Depends(require_approved)):
    user_id = str(user["_id"])
    doc = db["gmail_tokens"].find_one({"user_id": user_id, "gmail_email": gmail_email})
    if doc:
        import httpx
        try:
            async with httpx.AsyncClient() as client:
                await client.post("https://oauth2.googleapis.com/revoke",
                    params={"token": doc.get("refresh_token", doc.get("access_token", ""))})
        except Exception:
            pass
        db["gmail_tokens"].delete_one({"user_id": user_id, "gmail_email": gmail_email})
    users_col.update_one({"_id": user["_id"]}, {"$pull": {"gmail_accounts": gmail_email}})
    return {"message": f"{gmail_email} disconnected"}


@router.get("/gmail/accounts")
async def get_gmail_accounts(user=Depends(require_approved)):
    docs = list(db["gmail_tokens"].find(
        {"user_id": str(user["_id"])},
        {"_id": 0, "access_token": 0, "refresh_token": 0}
    ))
    for d in docs:
        if d.get("connected_at"): d["connected_at"] = d["connected_at"].isoformat()
        if d.get("last_used"): d["last_used"] = d["last_used"].isoformat()
    return docs


# ── Send ──────────────────────────────────────────────────────────────────────

async def send_single_gmail(access_token: str, from_email: str, bcc_list: list, subject: str, body: str, track_pixel: str = "") -> dict:
    import base64, httpx
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_email
    msg["Bcc"]     = ", ".join(bcc_list)
    msg.attach(MIMEText(body, "plain"))

    html_body = body.replace("\n", "<br>")
    if track_pixel:
        html_body += f'<br><img src="{track_pixel}" width="1" height="1" style="opacity:0;position:absolute;" alt="">'
    msg.attach(MIMEText(f"<div style='font-family:Arial,sans-serif;font-size:14px;line-height:1.6'>{html_body}</div>", "html"))
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            json={"raw": raw},
        )
    if resp.status_code not in [200, 201]:
        error = resp.json().get("error", {}).get("message", "Send failed")
        raise Exception(f"Gmail send failed for {from_email}: {error}")
    return resp.json()


@router.post("/gmail/send-batch")
async def send_batch_gmail(payload: dict, user=Depends(require_approved)):
    bcc_list       = payload.get("bcc", [])
    subject        = payload.get("subject", "")
    body           = payload.get("body", "")
    track_pixel    = payload.get("track_pixel", "")
    account_emails = payload.get("accounts", [])

    if not bcc_list:       raise HTTPException(400, detail="No recipients")
    if not subject:        raise HTTPException(400, detail="Subject required")
    if not body:           raise HTTPException(400, detail="Body required")
    if not account_emails: raise HTTPException(400, detail="No Gmail accounts selected")

    user_id = str(user["_id"])
    connected = list(db["gmail_tokens"].find({"user_id": user_id}))
    connected_emails = [d["gmail_email"] for d in connected]
    for acc in account_emails:
        if acc not in connected_emails:
            raise HTTPException(403, detail=f"{acc} is not connected to your account")

    # Split BCC evenly across selected accounts
    chunk_size = math.ceil(len(bcc_list) / len(account_emails))
    chunks = [bcc_list[i:i + chunk_size] for i in range(0, len(bcc_list), chunk_size)]

    results = []
    total_sent = 0

    for i, acc_email in enumerate(account_emails):
        chunk = chunks[i] if i < len(chunks) else []
        if not chunk:
            continue
        try:
            access_token = await get_valid_token(user_id, acc_email)
            result = await send_single_gmail(access_token, acc_email, chunk, subject, body, track_pixel)
            total_sent += len(chunk)
            db["gmail_tokens"].update_one(
                {"user_id": user_id, "gmail_email": acc_email},
                {"$inc": {"send_count": len(chunk)}, "$set": {"last_used": datetime.utcnow()}}
            )
            db["gmail_sends"].insert_one({
                "user_id": user_id, "user_name": user["name"],
                "gmail_email": acc_email, "bcc_count": len(chunk),
                "subject": subject, "sent_at": datetime.utcnow(),
                "message_id": result.get("id", ""),
            })
            results.append({"account": acc_email, "sent": len(chunk), "success": True})
        except Exception as e:
            results.append({"account": acc_email, "sent": 0, "success": False, "error": str(e)})

    if total_sent > 0:
        users_col.update_one({"_id": user["_id"]}, {"$inc": {"emails_scouted": total_sent}})

    return {"total_sent": total_sent, "accounts_used": len(account_emails), "results": results}


# ── Replies ───────────────────────────────────────────────────────────────────

@router.get("/gmail/replies")
async def get_replies(user=Depends(require_approved)):
    user_id = str(user["_id"])
    accounts = list(db["gmail_tokens"].find({"user_id": user_id}))
    if not accounts:
        raise HTTPException(403, detail="No Gmail accounts connected")

    import httpx
    total_replies = 0
    account_results = []

    for acc in accounts:
        try:
            access_token = await get_valid_token(user_id, acc["gmail_email"])
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    "https://gmail.googleapis.com/gmail/v1/users/me/messages",
                    headers={"Authorization": f"Bearer {access_token}"},
                    params={"q": "in:inbox newer_than:7d", "maxResults": 50}
                )
            count = len(resp.json().get("messages", []))
            total_replies += count
            account_results.append({"account": acc["gmail_email"], "replies": count})
        except Exception as e:
            account_results.append({"account": acc["gmail_email"], "replies": 0, "error": str(e)})

    return {"total_replies": total_replies, "accounts": account_results, "checked_at": datetime.utcnow().isoformat()}


# ── Admin ─────────────────────────────────────────────────────────────────────

@router.get("/admin/gmail/stats")
async def gmail_stats(admin=Depends(require_admin)):
    connected = db["gmail_tokens"].count_documents({})
    users_with_gmail = len(db["gmail_tokens"].distinct("user_id"))
    sends = list(db["gmail_sends"].find({}, {"_id": 0}).sort("sent_at", -1).limit(50))
    for s in sends:
        if s.get("sent_at"): s["sent_at"] = s["sent_at"].isoformat()
    pipeline = [
        {"$group": {"_id": "$gmail_email", "total_sent": {"$sum": "$bcc_count"}, "sends": {"$sum": 1}}},
        {"$sort": {"total_sent": -1}}, {"$limit": 20},
    ]
    per_account = list(db["gmail_sends"].aggregate(pipeline))
    for a in per_account:
        a["account"] = a.pop("_id")
    return {
        "total_accounts": connected, "users_with_gmail": users_with_gmail,
        "total_sends": db["gmail_sends"].count_documents({}),
        "recent_sends": sends, "per_account_stats": per_account,
    }
