import dns.resolver
import smtplib
import socket
import random
import string
from email_validator import validate_email, EmailNotValidError
from config import SMTP_TIMEOUT, FROM_EMAIL, RETRY_COUNT


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

    def check_mx_records(self, domain):
        try:
            mx_records = dns.resolver.resolve(domain, "MX")
            mx_hosts = sorted([(r.preference, str(r.exchange)) for r in mx_records])
            return True, mx_hosts[0][1]
        except Exception:
            return False, None

    def is_disposable(self, domain):
        return domain in self.disposable_domains

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
                    return True, "Mailbox confirmed"
                elif code in [450, 451, 452]:
                    return None, f"Greylisted or temp issue ({code})"
                elif code in [550, 551, 552, 553, 554]:
                    return False, f"Mailbox does not exist ({code})"
                elif code == 521:
                    return False, f"Domain does not accept mail ({code})"
                elif code == 525:
                    return False, f"User account disabled ({code})"
                else:
                    return False, f"SMTP rejected ({code})"
            except socket.timeout:
                if attempt == RETRY_COUNT - 1:
                    return None, "SMTP timeout"
            except Exception as e:
                if attempt == RETRY_COUNT - 1:
                    return None, str(e)
        return None, "Verification failed"

    def detect_catch_all(self, domain, mx_record):
        fake_user = "".join(random.choices(string.ascii_lowercase, k=14))
        result, _ = self.smtp_verify(f"{fake_user}@{domain}", mx_record)
        return result is True

    def classify(self, valid_format, has_mx, smtp_valid, disposable, catch_all):
        """
        Three buckets — purely based on whether the email will deliver.
        Role-based is irrelevant for store owner outreach.

        delivers — send these. SMTP confirmed OR timeout with real domain.
        unknown  — catch-all domain. Server accepts everything so we cant confirm.
        bounce   — hard signals. Do not send.
        """
        # Hard bounce signals
        if not valid_format:
            return "bounce", "HIGH"
        if not has_mx:
            return "bounce", "HIGH"
        if smtp_valid is False:
            return "bounce", "HIGH"
        if disposable:
            return "bounce", "HIGH"
        # Catch-all — cannot confirm individual mailbox
        if catch_all:
            return "unknown", "MEDIUM"
        # SMTP confirmed
        if smtp_valid is True:
            return "delivers", "LOW"
        # Timeout — server blocked probe but domain + MX are real
        # Treat as deliverable for cold email
        return "delivers", "LOW"

    def check_domain_exists(self, domain):
        """Extra signal — check if domain has ANY DNS record at all"""
        import dns.resolver
        try:
            dns.resolver.resolve(domain, "A")
            return True
        except Exception:
            pass
        try:
            dns.resolver.resolve(domain, "AAAA")
            return True
        except Exception:
            pass
        return False

    def check_smtp_error_code(self, code):
        """Classify SMTP error codes precisely"""
        hard_bounce = [550, 551, 552, 553, 554, 555, 500, 501, 503, 521, 525]
        soft_bounce = [421, 450, 451, 452]
        if code in hard_bounce:
            return "hard"
        if code in soft_bounce:
            return "soft"
        return "unknown"

    def verify(self, email: str) -> dict:
        email = email.strip().lower()
        result = {
            "email": email,
            "format_valid": False,
            "mx_valid": False,
            "smtp_valid": None,
            "catch_all": False,
            "disposable": False,
            "risk": "HIGH",
            "category": "bounce",
            "sendable": False,
            "message": "",
        }

        if not self.validate_format(email):
            result["message"] = "Invalid email format"
            return result
        result["format_valid"] = True

        domain = self.get_domain(email)
        result["disposable"] = self.is_disposable(domain)

        # Extra signal — check domain exists at all before MX lookup
        if not self.check_domain_exists(domain):
            result["message"] = "Domain does not exist"
            return result

        mx_valid, mx_record = self.check_mx_records(domain)
        if not mx_valid:
            result["message"] = "No MX records — domain does not accept email"
            return result
        result["mx_valid"] = True

        smtp_valid, smtp_message = self.smtp_verify(email, mx_record)
        result["smtp_valid"] = smtp_valid
        result["message"] = smtp_message

        try:
            result["catch_all"] = self.detect_catch_all(domain, mx_record)
        except Exception:
            pass

        category, risk = self.classify(
            result["format_valid"],
            result["mx_valid"],
            result["smtp_valid"],
            result["disposable"],
            result["catch_all"],
        )

        result["risk"] = risk
        result["category"] = category
        result["sendable"] = category != "bounce"

        return result
