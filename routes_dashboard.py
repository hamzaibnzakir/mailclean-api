from fastapi import APIRouter, Depends
from auth import require_approved, require_admin, db
from datetime import datetime, timedelta
from bson import ObjectId

router = APIRouter()

def date_ranges():
    now = datetime.utcnow()
    today_start     = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start      = today_start - timedelta(days=now.weekday())
    month_start     = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return today_start, week_start, month_start

def count_logs(collection, user_id=None, since=None):
    query = {}
    if user_id:
        query["user_id"] = str(user_id)
    if since:
        query["sent_at"] = {"$gte": since}
    return db[collection].count_documents(query)

def sum_field(collection, field, user_id=None, since=None):
    query = {}
    if user_id:
        query["user_id"] = str(user_id)
    if since:
        query["sent_at"] = {"$gte": since}
    pipeline = [{"$match": query}, {"$group": {"_id": None, "total": {"$sum": f"${field}"}}}]
    result = list(db[collection].aggregate(pipeline))
    return result[0]["total"] if result else 0

def daily_series(collection, field, user_id=None, days=30):
    """Returns list of {date, value} for last N days"""
    now = datetime.utcnow()
    series = []
    for i in range(days - 1, -1, -1):
        day = now - timedelta(days=i)
        start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        end   = start + timedelta(days=1)
        query = {"sent_at": {"$gte": start, "$lt": end}}
        if user_id:
            query["user_id"] = str(user_id)
        if field == "count":
            val = db[collection].count_documents(query)
        else:
            pipeline = [{"$match": query}, {"$group": {"_id": None, "total": {"$sum": f"${field}"}}}]
            res = list(db[collection].aggregate(pipeline))
            val = res[0]["total"] if res else 0
        series.append({"date": start.strftime("%b %d"), "value": val})
    return series


# ─── User dashboard ───────────────────────────────────────────────────────────

@router.get("/dashboard/me")
async def my_dashboard(user=Depends(require_approved)):
    today, week, month = date_ranges()
    uid = str(user["_id"])

    # Verification logs — we use verify_logs collection
    v = {
        "today":   count_logs("verify_logs", uid, today),
        "week":    count_logs("verify_logs", uid, week),
        "month":   count_logs("verify_logs", uid, month),
        "total":   user.get("emails_verified", 0),
    }

    # Scout logs
    s = {
        "today":        sum_field("scout_logs", "email_count", uid, today),
        "week":         sum_field("scout_logs", "email_count", uid, week),
        "month":        sum_field("scout_logs", "email_count", uid, month),
        "total":        user.get("emails_scouted", 0),
        "batches_sent": user.get("batches_sent", 0),
    }

    # 30-day chart data
    verify_series = daily_series("verify_logs", "email_count", uid, 30)
    scout_series  = daily_series("scout_logs",  "email_count", uid, 30)

    # Recent activity
    recent = list(db["scout_logs"].find(
        {"user_id": uid}, {"_id": 0}
    ).sort("sent_at", -1).limit(10))
    for r in recent:
        if r.get("sent_at"):
            r["sent_at"] = r["sent_at"].isoformat()

    return {
        "verified": v,
        "scouted":  s,
        "verify_series": verify_series,
        "scout_series":  scout_series,
        "recent_activity": recent,
    }


# ─── Admin dashboard ──────────────────────────────────────────────────────────

@router.get("/dashboard/admin")
async def admin_dashboard(admin=Depends(require_admin)):
    today, week, month = date_ranges()

    # Platform totals
    total_users    = db["users"].count_documents({})
    pending_users  = db["users"].count_documents({"status": "pending"})
    approved_users = db["users"].count_documents({"status": "approved"})

    v = {
        "today": count_logs("verify_logs", since=today),
        "week":  count_logs("verify_logs", since=week),
        "month": count_logs("verify_logs", since=month),
    }

    s = {
        "today": sum_field("scout_logs", "email_count", since=today),
        "week":  sum_field("scout_logs", "email_count", since=week),
        "month": sum_field("scout_logs", "email_count", since=month),
    }

    # 30-day platform chart
    verify_series = daily_series("verify_logs", "email_count", days=30)
    scout_series  = daily_series("scout_logs",  "email_count", days=30)

    # Top users by scouted this month
    pipeline = [
        {"$match": {"sent_at": {"$gte": month}}},
        {"$group": {"_id": "$user_id", "name": {"$first": "$user_name"}, "email": {"$first": "$user_email"}, "total": {"$sum": "$email_count"}}},
        {"$sort": {"total": -1}},
        {"$limit": 10},
    ]
    top_users = list(db["scout_logs"].aggregate(pipeline))
    for u in top_users:
        u["user_id"] = str(u.pop("_id"))

    # Recent scout activity across all users
    recent = list(db["scout_logs"].find({}, {"_id": 0}).sort("sent_at", -1).limit(20))
    for r in recent:
        if r.get("sent_at"):
            r["sent_at"] = r["sent_at"].isoformat()

    return {
        "users": {"total": total_users, "pending": pending_users, "approved": approved_users},
        "verified": v,
        "scouted": s,
        "verify_series": verify_series,
        "scout_series": scout_series,
        "top_users": top_users,
        "recent_activity": recent,
    }
