"""Audit logging: MongoDB if reachable, otherwise a local JSONL file."""
import json
import threading
from datetime import datetime, timezone

from . import config

SENSITIVE_KEYS = ("password", "secret", "token", "code")


def mask_ip(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3] + ["x"]) if len(parts) == 4 else ip


class AuditStore:
    def __init__(self):
        self.col = None
        self.path = "audit_log.jsonl"
        self.lock = threading.Lock()
        try:
            from pymongo import MongoClient
            client = MongoClient(config.MONGO_URL, serverSelectionTimeoutMS=1500)
            client.admin.command("ping")
            self.col = client[config.MONGO_DB]["audit_logs"]
            print("[audit] using MongoDB")
        except Exception as exc:
            print(f"[audit] MongoDB unavailable ({type(exc).__name__}); using {self.path}")

    def log(self, event_type: str, username: str, **data):
        clean = {k: v for k, v in data.items() if not any(s in k.lower() for s in SENSITIVE_KEYS)}
        if "ip" in clean and isinstance(clean["ip"], str):
            clean["ip"] = mask_ip(clean["ip"])
        doc = {"ts": datetime.now(timezone.utc).isoformat(), "type": event_type, "username": username, **clean}
        if self.col is not None:
            self.col.insert_one(dict(doc))
        else:
            with self.lock, open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(doc) + "\n")

    def recent(self, limit=50, username=None, types=None):
        if self.col is not None:
            q = {}
            if username:
                q["username"] = username
            if types:
                q["type"] = {"$in": types}
            return list(self.col.find(q, {"_id": 0}).sort("ts", -1).limit(limit))
        try:
            with open(self.path, encoding="utf-8") as f:
                rows = [json.loads(line) for line in f if line.strip()]
        except FileNotFoundError:
            return []
        rows.reverse()
        if username:
            rows = [r for r in rows if r.get("username") == username]
        if types:
            rows = [r for r in rows if r.get("type") in types]
        return rows[:limit]


audit = AuditStore()
