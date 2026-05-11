import re
import dns.resolver
import smtplib
import socket
import random
import string
import pandas as pd
from email_validator import validate_email, EmailNotValidError
from concurrent.futures import ThreadPoolExecutor
from config import SMTP_TIMEOUT, FROM_EMAIL, RETRY_COUNT

ROLE_BASED_PREFIXES = [
    "admin", "support", "info", "contact", "sales",
    "help", "billing", "team", "noreply", "no-reply",
    "hello", "mail", "office", "abuse", "postmaster",
]


class EmailVerifier:
    def __init__(self):
        self.disposable_domains = self.load_disposable_domains()

    def load_disposable_domains(self):
        try:
            with open("disposable_domains.txt", "r") as f:
                return set(line.strip().lower() for line in f if line.strip())
        except FileNotFoundError:
            return set()

    def validate_format(self, email):
        try:
            validate_email(email)
            return True
        except EmailNotValidError:
            return False

    def get_domain(self, email):
        return email.split("@")[1].lower()

    def get_username(self, email):
        return email.split("@")[0].lower()

    def check_mx_records(self, domain):
        try:
            mx_records = dns.resolver.resolve(domain, "MX")
            mx_hosts = sorted([(r.preference, str(r.exchange)) for r in mx_records])
            return True, mx_hosts[0][1]
        except Exception:
            return False, None

    def is_disposable(self, domain):
        return domain in self.disposable_domains

    def is_role_based(self, username):
        return username in ROLE_BASED_PREFIXES

    def smtp_verify(self, email, mx_record):
        for attempt in range(RETRY_COUNT):
            try:
                server = smtplib.SMTP(timeout=SMTP_TIMEOUT)
                server.connect(mx_record)
                server.helo("localhost")
                server.mail(FROM_EMAIL)
                code, message = server.rcpt(email)
                server.quit()

                if code == 250:
                    return True, "Mailbox exists"
                elif code in [450, 451, 452]:
                    return None, "Greylisted or temporary issue"
                else:
                    return False, f"SMTP rejected: {code}"
            except socket.timeout:
                if attempt == RETRY_COUNT - 1:
                    return None, "SMTP timeout"
            except Exception as e:
                if attempt == RETRY_COUNT - 1:
                    return None, str(e)
        return None, "Verification failed after retries"

    def detect_catch_all(self, domain, mx_record):
        fake_user = "".join(random.choices(string.ascii_lowercase, k=14))
        fake_email = f"{fake_user}@{domain}"
        result, _ = self.smtp_verify(fake_email, mx_record)
        return result is True

    def calculate_risk(self, valid_format, has_mx, smtp_valid, disposable, catch_all, role_based):
        score = 100
        if not valid_format:
            score -= 60
        if not has_mx:
            score -= 40
        if smtp_valid is False:
            score -= 50
        if disposable:
            score -= 20
        if catch_all:
            score -= 15
        if role_based:
            score -= 10
        if score >= 85:
            return "LOW"
        elif score >= 60:
            return "MEDIUM"
        return "HIGH"

    def verify(self, email: str) -> dict:
        email = email.strip().lower()
        result = {
            "email": email,
            "format_valid": False,
            "mx_valid": False,
            "smtp_valid": None,
            "catch_all": False,
            "disposable": False,
            "role_based": False,
            "risk": "HIGH",
            "message": "",
        }

        if not self.validate_format(email):
            result["message"] = "Invalid format"
            return result
        result["format_valid"] = True

        domain = self.get_domain(email)
        username = self.get_username(email)
        result["disposable"] = self.is_disposable(domain)
        result["role_based"] = self.is_role_based(username)

        mx_valid, mx_record = self.check_mx_records(domain)
        if not mx_valid:
            result["message"] = "No MX records found"
            return result
        result["mx_valid"] = True

        smtp_valid, smtp_message = self.smtp_verify(email, mx_record)
        result["smtp_valid"] = smtp_valid
        result["message"] = smtp_message

        try:
            result["catch_all"] = self.detect_catch_all(domain, mx_record)
        except Exception:
            pass

        result["risk"] = self.calculate_risk(
            result["format_valid"],
            result["mx_valid"],
            result["smtp_valid"],
            result["disposable"],
            result["catch_all"],
            result["role_based"],
        )

        return result
