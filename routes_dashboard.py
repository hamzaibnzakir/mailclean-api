from fastapi import APIRouter, Depends, HTTPException
from auth import require_approved, require_admin, db, users_col
from datetime import datetime, timedelta
from bson import ObjectId

router = APIRouter()


def date_ranges():
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start  = today_start - timedelta(days=now.weekday())
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return today_start, week_start, month_start


def sum_field(collection, field, user_id=None, since=None):
    query = {}
    if user_id:
        query["user_id"] = str(user_id)
    if since:
        query["sent_at"] = {"$gte": since}
    pipeline = [
        {"$match": query},
        {"$group": {"_id": None, "total": {"$sum": "$" + field}}}
    ]
    result = list(db[collection].aggregate(pipeline))
    return int(result[0]["total"]) if result else 0


def count_docs(collection, user_id=None, since=None):
    query = {}
    if user_id:
        query["user_id"] = str(user_id)
    if since:
        query["sent_at"] = {"$gte": since}
    return db[collection].count_documents(query)


def daily_series(collection, field, user_id=None, days=30):
    now = datetime.utcnow()
    series = []
    for i in range(days - 1, -1, -1):
        day   = now - timedelta(days=i)
        start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        end   = start + timedelta(days=1)
        query = {"sent_at": {"$gte": start, "$lt": end}}
        if user_id:
            query["user_id"] = str(user_id)
        pipeline = [
            {"$match": query},
            {"$group": {"_id": None, "total": {"$sum": "$" + field}}}
        ]
        res = list(db[collection].aggregate(pipeline))
        val = int(res[0]["total"]) if res else 0
        series.append({"date": day.strftime("%b %d"), "value": val})
    return series


# ── User dashboard ────────────────────────────────────────────────────────────

@router.get("/dashboard/me")
async def my_dashboard(user=Depends(require_approved)):
    today, week, month = date_ranges()
    uid = str(user["_id"])

    verified = {
        "today": sum_field("verify_logs", "email_count", uid, today),
        "week":  sum_field("verify_logs", "email_count", uid, week),
        "month": sum_field("verify_logs", "email_count", uid, month),
        "total": sum_field("verify_logs", "email_count", uid),
    }

    scouted = {
        "today":         sum_field("scout_logs", "email_count", uid, today),
        "week":          sum_field("scout_logs", "email_count", uid, week),
        "month":         sum_field("scout_logs", "email_count", uid, month),
        "total":         sum_field("scout_logs", "email_count", uid),
        "batches_today": count_docs("scout_logs", uid, today),
        "batches_week":  count_docs("scout_logs", uid, week),
        "batches_month": count_docs("scout_logs", uid, month),
        "batches_total": count_docs("scout_logs", uid),
    }

    verify_series = daily_series("verify_logs", "email_count", uid, 30)
    scout_series  = daily_series("scout_logs",  "email_count", uid, 30)

    recent = list(db["scout_logs"].find(
        {"user_id": uid}, {"_id": 0}
    ).sort("sent_at", -1).limit(10))
    for r in recent:
        if r.get("sent_at"):
            r["sent_at"] = r["sent_at"].isoformat()

    return {
        "verified": verified,
        "scouted":  scouted,
        "verify_series": verify_series,
        "scout_series":  scout_series,
        "recent_activity": recent,
    }


# ── Admin dashboard ───────────────────────────────────────────────────────────

@router.get("/dashboard/admin")
async def admin_dashboard(admin=Depends(require_admin)):
    today, week, month = date_ranges()

    total_users    = users_col.count_documents({})
    pending_users  = users_col.count_documents({"status": "pending"})
    approved_users = users_col.count_documents({"status": "approved"})
    suspended      = users_col.count_documents({"status": "suspended"})
    banned         = users_col.count_documents({"status": "banned"})

    verified = {
        "today": sum_field("verify_logs", "email_count", since=today),
        "week":  sum_field("verify_logs", "email_count", since=week),
        "month": sum_field("verify_logs", "email_count", since=month),
        "total": sum_field("verify_logs", "email_count"),
    }

    scouted = {
        "today": sum_field("scout_logs", "email_count", since=today),
        "week":  sum_field("scout_logs", "email_count", since=week),
        "month": sum_field("scout_logs", "email_count", since=month),
        "total": sum_field("scout_logs", "email_count"),
    }

    verify_series = daily_series("verify_logs", "email_count", days=30)
    scout_series  = daily_series("scout_logs",  "email_count", days=30)

    pipeline = [
        {"$match": {"sent_at": {"$gte": month}}},
        {"$group": {
            "_id":     "$user_id",
            "name":    {"$first": "$user_name"},
            "email":   {"$first": "$user_email"},
            "total":   {"$sum": "$email_count"},
            "batches": {"$sum": 1},
        }},
        {"$sort": {"total": -1}},
        {"$limit": 10},
    ]
    top_users = list(db["scout_logs"].aggregate(pipeline))
    for u in top_users:
        u["user_id"] = str(u.pop("_id"))

    recent = list(db["scout_logs"].find({}, {"_id": 0}).sort("sent_at", -1).limit(20))
    for r in recent:
        if r.get("sent_at"):
            r["sent_at"] = r["sent_at"].isoformat()

    return {
        "users":    {"total": total_users, "pending": pending_users, "approved": approved_users, "suspended": suspended, "banned": banned},
        "verified": verified,
        "scouted":  scouted,
        "verify_series": verify_series,
        "scout_series":  scout_series,
        "top_users": top_users,
        "recent_activity": recent,
    }


# ── Admin user detail ─────────────────────────────────────────────────────────

@router.get("/dashboard/admin/user/{user_id}")
async def admin_user_detail(user_id: str, admin=Depends(require_admin)):
    try:
        user = users_col.find_one({"_id": ObjectId(user_id)})
    except Exception:
        raise HTTPException(400, detail="Invalid user ID")
    if not user:
        raise HTTPException(404, detail="User not found")

    today, week, month = date_ranges()
    uid = str(user["_id"])

    verified = {
        "today": sum_field("verify_logs", "email_count", uid, today),
        "week":  sum_field("verify_logs", "email_count", uid, week),
        "month": sum_field("verify_logs", "email_count", uid, month),
        "total": sum_field("verify_logs", "email_count", uid),
    }

    scouted = {
        "today":         sum_field("scout_logs", "email_count", uid, today),
        "week":          sum_field("scout_logs", "email_count", uid, week),
        "month":         sum_field("scout_logs", "email_count", uid, month),
        "total":         sum_field("scout_logs", "email_count", uid),
        "batches_today": count_docs("scout_logs", uid, today),
        "batches_week":  count_docs("scout_logs", uid, week),
        "batches_month": count_docs("scout_logs", uid, month),
        "batches_total": count_docs("scout_logs", uid),
    }

    verify_series = daily_series("verify_logs", "email_count", uid, 30)
    scout_series  = daily_series("scout_logs",  "email_count", uid, 30)

    recent_scouts = list(db["scout_logs"].find(
        {"user_id": uid}, {"_id": 0}
    ).sort("sent_at", -1).limit(20))
    for r in recent_scouts:
        if r.get("sent_at"):
            r["sent_at"] = r["sent_at"].isoformat()

    scout_rate = round((scouted["total"] / verified["total"]) * 100) if verified["total"] > 0 else 0

    return {
        "user": {
            "id":          uid,
            "name":        user.get("name", ""),
            "email":       user.get("email", ""),
            "role":        user.get("role", "user"),
            "status":      user.get("status", "pending"),
            "created_at":  user["created_at"].isoformat() if user.get("created_at") else None,
            "last_active": user["last_active"].isoformat() if user.get("last_active") else None,
        },
        "verified":      verified,
        "scouted":       scouted,
        "scout_rate":    scout_rate,
        "verify_series": verify_series,
        "scout_series":  scout_series,
        "recent_scouts": recent_scouts,
    }
