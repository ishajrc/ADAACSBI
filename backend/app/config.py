import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./adaptive.db")
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
MONGO_DB = "adaptive_access"

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me-dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 60
MFA_TOKEN_MINUTES = 5

# Login protection
MAX_FAILED_LOGINS = 5
LOGIN_LOCKOUT_MINUTES = 15

# Resource-access protection
MAX_VIOLATIONS = 5
VIOLATION_LOCKOUT_SECONDS = 60

# Risk thresholds (0.0 - 1.0)
RISK_MFA = 0.30
RISK_BLOCK = 0.70

# Threat intelligence (demo values)
BLACKLISTED_IPS = {ip for ip in os.getenv("BLACKLISTED_IPS", "203.0.113.66").split(",") if ip}
RESTRICTED_COUNTRIES = {"KP", "IR"}
IMPOSSIBLE_TRAVEL_HOURS = 2
DEFAULT_COUNTRY = os.getenv("DEFAULT_COUNTRY", "IN")

# Lets the frontend simulate IP/country via headers. TURN OFF in production.
ENABLE_SIMULATION = os.getenv("ENABLE_SIMULATION", "1") == "1"

MANAGED_DEVICES = {"Corporate Laptop", "Corporate Desktop"}

RESOURCES = {
    101: {"name": "Quarterly Budget", "department": "Finance", "sensitivity": 1},
    102: {"name": "Payroll Archive", "department": "Finance", "sensitivity": 2},
    103: {"name": "Source Code Vault", "department": "Engineering", "sensitivity": 3},
    104: {"name": "Company Handbook", "department": "General", "sensitivity": 1},
}
