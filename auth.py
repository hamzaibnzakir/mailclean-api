import os
import jwt
import bcrypt
from datetime import datetime, timedelta
from pymongo import MongoClient
from bson import ObjectId
from fastapi import HTTPException, Header
from typing import Optional

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
JWT_SECRET = os.getenv("JWT_SECRET", "change-this-secret-in-production")
JWT_EXPIRE_HOURS = 24
MAIN_ADMIN_EMAIL = os.getenv("MAIN_ADMIN_EMAIL", "admin@brainboxecomlab.com")

client = MongoClient(MONGO_URI)
db = client["mailclean"]
users_col = db["users"]

# Indexes
users_col.create_index("email", unique=True)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def create_token(user_id: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ")[1]
    payload = decode_token(token)
    user = users_col.find_one({"_id": ObjectId(payload["sub"])})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if user.get("status") == "banned":
        raise HTTPException(status_code=403, detail="Account banned")
    if user.get("status") == "suspended":
        raise HTTPException(status_code=403, detail="Account suspended")
    return user


def require_approved(authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    if user.get("status") != "approved":
        raise HTTPException(status_code=403, detail="Account pending approval")
    return user


def require_admin(authorization: Optional[str] = Header(None)):
    user = get_current_user(authorization)
    if user.get("role") not in ["admin", "main_admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def seed_main_admin():
    """Create main admin on first run if doesn't exist"""
    existing = users_col.find_one({"role": "main_admin"})
    if not existing:
        users_col.insert_one({
            "email": MAIN_ADMIN_EMAIL,
            "password": hash_password(os.getenv("MAIN_ADMIN_PASSWORD", "admin123")),
            "name": "Main Admin",
            "role": "main_admin",
            "status": "approved",
            "created_at": datetime.utcnow(),
            "emails_verified": 0,
            "last_active": None,
        })
        print(f"Main admin created: {MAIN_ADMIN_EMAIL}")
