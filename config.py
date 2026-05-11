import os

SMTP_TIMEOUT = int(os.getenv("SMTP_TIMEOUT", 10))
MAX_THREADS = int(os.getenv("MAX_THREADS", 30))
FROM_EMAIL = os.getenv("FROM_EMAIL", "verify@yourdomain.com")
RETRY_COUNT = int(os.getenv("RETRY_COUNT", 2))
