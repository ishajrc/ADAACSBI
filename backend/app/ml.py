"""ML anomaly engine: Logistic Regression + Decision Tree + Isolation Forest (majority vote)."""
import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from . import config

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "risk_models.joblib")
FEATURES = ["hour", "weekday", "sensitivity", "clearance_gap", "trusted_network",
            "managed_device", "new_device", "new_ip", "violations", "request_burst"]
_models = None


def build_features(user, res: dict, ctx: dict) -> list:
    return [
        ctx["hour"], ctx["weekday"], res["sensitivity"],
        user.clearance_level - res["sensitivity"],
        int(ctx["trusted_network"]), int(ctx["device_type"] in config.MANAGED_DEVICES),
        int(ctx["is_new_device"]), int(ctx["is_new_ip"]),
        min(user.violation_count or 0, 5), min(user.request_burst_count or 0, 30),
    ]


def synthetic_dataset(n=6000, seed=42):
    rng = np.random.default_rng(seed)
    n_norm = int(n * 0.8)
    n_anom = n - n_norm

    def normal(m):
        return np.column_stack([
            rng.integers(8, 19, m), rng.integers(0, 5, m), rng.integers(1, 4, m), rng.integers(0, 3, m),
            rng.random(m) < 0.97, rng.random(m) < 0.92, rng.random(m) < 0.04, rng.random(m) < 0.05,
            rng.choice([0, 1], m, p=[0.9, 0.1]), rng.integers(0, 12, m)])

    def anomalous(m):
        return np.column_stack([
            rng.integers(0, 24, m), rng.integers(0, 7, m), rng.integers(1, 4, m), rng.integers(-2, 3, m),
            rng.random(m) < 0.5, rng.random(m) < 0.5, rng.random(m) < 0.6, rng.random(m) < 0.6,
            rng.integers(0, 6, m), rng.integers(5, 31, m)])

    X = np.vstack([normal(n_norm), anomalous(n_anom)]).astype(float)
    y = np.array([0] * n_norm + [1] * n_anom)
    return X, y


def train(save=True):
    X, y = synthetic_dataset()
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000)).fit(X_tr, y_tr)
    dt = DecisionTreeClassifier(max_depth=5, random_state=42).fit(X_tr, y_tr)
    iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42).fit(X_tr[y_tr == 0])

    print("Model evaluation on held-out synthetic data:")
    for name, pred in [("LogisticRegression", lr.predict(X_te)), ("DecisionTree", dt.predict(X_te)),
                       ("IsolationForest", (iso.predict(X_te) == -1).astype(int))]:
        print(f"  {name:19s} acc={accuracy_score(y_te, pred):.3f} "
              f"prec={precision_score(y_te, pred):.3f} rec={recall_score(y_te, pred):.3f}")
    models = {"lr": lr, "dt": dt, "iso": iso}
    if save:
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        joblib.dump(models, MODEL_PATH)
    return models


def get_models():
    global _models
    if _models is None:
        _models = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else train()
    return _models


def predict(features: list) -> dict:
    m = get_models()
    x = np.array([features], dtype=float)
    p_lr = float(m["lr"].predict_proba(x)[0][1])
    p_dt = float(m["dt"].predict_proba(x)[0][1])
    iso_flag = int(m["iso"].predict(x)[0] == -1)
    votes = int(p_lr > 0.5) + int(p_dt > 0.5) + iso_flag
    return {"risk": round((p_lr + p_dt + iso_flag) / 3, 2), "is_anomaly": votes >= 2,
            "votes": votes, "p_lr": round(p_lr, 2), "p_dt": round(p_dt, 2), "iso": iso_flag}


if __name__ == "__main__":
    train()
    print("Saved to", os.path.abspath(MODEL_PATH))
