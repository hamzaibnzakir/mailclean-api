from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from auth import require_approved, require_admin, db, users_col
from bson import ObjectId
from datetime import datetime
import os
import json

router = APIRouter()

GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
REDIRECT_URI         = "https://api.brainboxecomlab.com/auth/google/callback"
FRONTEND_URL         = "https://verify.brainboxecomlab.com"

SCOPES = [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.readonly",
    "openid",
    "email",
    "profile",
]


def get_google_auth_url(state: str) -> str:
    import urllib.parse
    params = {
        "client_id":     GOOGLE_CLIENT_ID,
        "redirect_uri":  REDIRECT_URI,
        "response_type": "code",
        "scope":         " ".join(SCOPES),
        "access_type":   "offline",
        "prompt":        "consent",
        "state":         state,
    }
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)


async def exchange_code(code: str) -> dict:
    import httpx
    async with httpx.AsyncClient() as client:
        resp = await client.post("https://oauth2.googleapis.com/token", data={
            "code":          code,
            "client_id":     GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri":  REDIRECT_URI,
            "grant_type":    "authorization_code",
        })
        if resp.status_code != 200:
            raise HTTPException(400, detail=f"Token exchange failed: {resp.text}")
        return resp.json()


async def refresh_access_token(refresh_token: str) -> str:
    import httpx
    async with httpx.AsyncClient() as client:
        resp = await client.post("https://oauth2.googleapis.com/token", data={
            "refresh_token": refresh_token,
            "client_id":     GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "grant_type":    "refresh_token",
        })
        data = resp.json()
        if "access_token" not in data:
            raise HTTPException(400, detail="Failed to refresh token")
        return data["access_token"]


async def get_valid_token(user_id: str) -> str:
    """Get a valid access token — refresh if expired."""
    gmail_doc = db["gmail_tokens"].find_one({"user_id": user_id})
    if not gmail_doc:
        raise HTTPException(403, detail="Gmail not connected. Please connect Gmail in Settings.")

    # Check if expired
    import time
    if gmail_doc.get("expires_at", 0) < time.time() + 60:
        new_token = await refresh_access_token(gmail_doc["refresh_token"])
        import time as t
        db["gmail_tokens"].update_one(
            {"user_id": user_id},
            {"$set": {"access_token": new_token, "expires_at": t.time() + 3600}}
        )
        return new_token

    return gmail_doc["access_token"]


# ── OAuth flow ────────────────────────────────────────────────────────────────

@router.get("/auth/google/connect")
async def gmail_connect(user=Depends(require_approved)):
    """Redirect user to Google OAuth consent screen."""
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(500, detail="Google OAuth not configured")
    state = str(user["_id"])
    url = get_google_auth_url(state)
    return {"auth_url": url}


@router.get("/auth/google/callback")
async def gmail_callback(code: str = None, state: str = None, error: str = None):
    """Handle Google OAuth callback."""
    if error:
        return RedirectResponse(f"{FRONTEND_URL}/app?gmail_error={error}")
    if not code or not state:
        return RedirectResponse(f"{FRONTEND_URL}/app?gmail_error=missing_params")

    try:
        tokens = await exchange_code(code)
    except Exception as e:
        return RedirectResponse(f"{FRONTEND_URL}/app?gmail_error=exchange_failed")

    import time
    user_id = state

    # Get Gmail profile
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

    # Store tokens
    db["gmail_tokens"].update_one(
        {"user_id": user_id},
        {"$set": {
            "user_id":       user_id,
            "access_token":  tokens["access_token"],
            "refresh_token": tokens.get("refresh_token", ""),
            "expires_at":    time.time() + tokens.get("expires_in", 3600),
            "gmail_email":   gmail_email,
            "connected_at":  datetime.utcnow(),
            "scopes":        SCOPES,
        }},
        upsert=True
    )

    users_col.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"gmail_connected": True, "gmail_email": gmail_email}}
    )

    return RedirectResponse(f"{FRONTEND_URL}/app?gmail_connected=true")


@router.delete("/auth/google/disconnect")
async def gmail_disconnect(user=Depends(require_approved)):
    """Revoke Gmail access and delete tokens."""
    user_id = str(user["_id"])
    gmail_doc = db["gmail_tokens"].find_one({"user_id": user_id})

    if gmail_doc:
        # Revoke with Google
        import httpx
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    "https://oauth2.googleapis.com/revoke",
                    params={"token": gmail_doc.get("refresh_token", gmail_doc.get("access_token", ""))}
                )
        except Exception:
            pass
        db["gmail_tokens"].delete_one({"user_id": user_id})

    users_col.update_one(
        {"_id": user["_id"]},
        {"$set": {"gmail_connected": False, "gmail_email": None}}
    )
    return {"message": "Gmail disconnected"}


@router.get("/gmail/status")
async def gmail_status(user=Depends(require_approved)):
    """Check if Gmail is connected."""
    gmail_doc = db["gmail_tokens"].find_one({"user_id": str(user["_id"])})
    if not gmail_doc:
        return {"connected": False}
    return {
        "connected":    True,
        "gmail_email":  gmail_doc.get("gmail_email", ""),
        "connected_at": gmail_doc.get("connected_at", "").isoformat() if gmail_doc.get("connected_at") else "",
    }


# ── Send email via Gmail API ──────────────────────────────────────────────────

@router.post("/gmail/send-batch")
async def send_batch_gmail(payload: dict, user=Depends(require_approved)):
    """Send a batch email via Gmail API."""
    bcc_list = payload.get("bcc", [])
    subject  = payload.get("subject", "")
    body     = payload.get("body", "")
    track_pixel = payload.get("track_pixel", "")

    if not bcc_list:
        raise HTTPException(400, detail="No recipients provided")
    if not subject:
        raise HTTPException(400, detail="Subject is required")
    if not body:
        raise HTTPException(400, detail="Body is required")
    if len(bcc_list) > 500:
        raise HTTPException(400, detail="Max 500 BCC recipients per send")

    access_token = await get_valid_token(str(user["_id"]))

    # Build RFC 2822 email message
    import base64
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = user.get("gmail_email", user["email"])
    msg["Bcc"]     = ", ".join(bcc_list)

    # Plain text version
    msg.attach(MIMEText(body, "plain"))

    # HTML version with tracking pixel
    html_body = body.replace('\n', '<br>')
    if track_pixel:
        html_body += f'<br><img src="{track_pixel}" width="1" height="1" style="opacity:0;position:absolute;" alt="">'
    msg.attach(MIMEText(f"<div style='font-family:Arial,sans-serif;font-size:14px;line-height:1.6'>{html_body}</div>", "html"))

    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()

    # Send via Gmail API
    import httpx
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type":  "application/json",
            },
            json={"raw": raw},
        )

    if resp.status_code not in [200, 201]:
        error = resp.json().get("error", {}).get("message", "Send failed")
        raise HTTPException(400, detail=f"Gmail send failed: {error}")

    # Log the send
    db["gmail_sends"].insert_one({
        "user_id":     str(user["_id"]),
        "user_name":   user["name"],
        "user_email":  user["email"],
        "gmail_email": user.get("gmail_email", ""),
        "bcc_count":   len(bcc_list),
        "subject":     subject,
        "sent_at":     datetime.utcnow(),
        "message_id":  resp.json().get("id", ""),
    })

    return {
        "success":   True,
        "sent_to":   len(bcc_list),
        "message_id": resp.json().get("id", ""),
    }


# ── Read replies (gmail.readonly) ─────────────────────────────────────────────

@router.get("/gmail/replies")
async def get_replies(user=Depends(require_approved)):
    """Check for replies to outreach emails — uses gmail.readonly scope."""
    access_token = await get_valid_token(str(user["_id"]))

    import httpx
    async with httpx.AsyncClient() as client:
        # Search for replies in inbox (emails received, not sent by us)
        resp = await client.get(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages",
            headers={"Authorization": f"Bearer {access_token}"},
            params={
                "q":          "in:inbox newer_than:7d",
                "maxResults": 20,
            }
        )

    if resp.status_code != 200:
        raise HTTPException(400, detail="Could not fetch Gmail data")

    data      = resp.json()
    messages  = data.get("messages", [])
    reply_count = len(messages)

    # Log this read
    db["gmail_reads"].update_one(
        {"user_id": str(user["_id"])},
        {"$set": {
            "user_id":      str(user["_id"]),
            "last_checked": datetime.utcnow(),
            "reply_count":  reply_count,
        }},
        upsert=True
    )

    return {
        "reply_count": reply_count,
        "checked_at":  datetime.utcnow().isoformat(),
        "message":     f"Found {reply_count} recent messages in your inbox",
    }


# ── Admin: Gmail usage ────────────────────────────────────────────────────────

@router.get("/admin/gmail/stats")
async def gmail_stats(admin=Depends(require_admin)):
    connected = db["gmail_tokens"].count_documents({})
    sends     = list(db["gmail_sends"].find({}, {"_id": 0}).sort("sent_at", -1).limit(50))
    for s in sends:
        if s.get("sent_at"): s["sent_at"] = s["sent_at"].isoformat()
    return {
        "connected_users": connected,
        "recent_sends":    sends,
        "total_sends":     db["gmail_sends"].count_documents({}),
    }
