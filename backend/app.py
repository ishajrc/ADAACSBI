from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from datetime import datetime, timedelta
from pymongo import MongoClient

app = Flask(__name__)

# --------------------------
# Configuration
# --------------------------

app.config['SECRET_KEY'] = 'my_test_secret_123'

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Dunki2004@localhost:5432/adaccsbi_udb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --------------------------
# MongoDB Atlas Connection
# --------------------------

mongo_client = MongoClient("mongodb+srv://ishaljrc_mpdb:Lowk_crying@adaccs-cluster.lemtf4t.mongodb.net/?appName=adaccs-cluster")
mongo_db = mongo_client["adaccs_logs_db"]
logs_collection = mongo_db["access_logs"]


# --------------------------
# User Model (PostgreSQL)
# --------------------------

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default="pending")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"




# --------------------------
# Role Decorator (Logs to MongoDB)
# --------------------------

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):

            role = request.headers.get("Role")
            username = request.headers.get("Username")

            if not role or not username:
                return jsonify({"error": "Missing headers"}), 403

            endpoint = request.path

            # Calculate risk
            risk_score = calculate_risk(username, role, endpoint)

            decision = "allowed"

            if role != required_role:
                decision = "denied"

            if risk_score >= 50:
                decision = "denied"

            # Log behavior to MongoDB
            logs_collection.insert_one({
                "username": username,
                "role": role,
                "endpoint": endpoint,
                "risk_score": risk_score,
                "decision": decision,
                "timestamp": datetime.utcnow()
            })

            if decision == "denied":
                return jsonify({
                    "error": "Access denied",
                    "risk_score": risk_score
                }), 403

            return f(*args, **kwargs)

        return wrapper
    return decorator

def calculate_risk(username, role, endpoint):
    risk_score = 0
    current_hour = datetime.utcnow().hour

    # 1️⃣ Unusual login time
    if current_hour < 8 or current_hour > 20:
        risk_score += 30

    # 2️⃣ Rapid request detection (last 1 minute)
    one_minute_ago = datetime.utcnow() - timedelta(minutes=1)

    recent_requests = logs_collection.count_documents({
        "username": username,
        "timestamp": {"$gte": one_minute_ago}
})
    recent_requests += 1

    if recent_requests > 5:
        extra = recent_requests - 5
        risk_score += 25 + (extra * 5)

 

    # 3️⃣ Role mismatch attempt
    if "admin" in endpoint and role != "admin":
        risk_score += 40

    return risk_score






# --------------------------
# Routes
# --------------------------

@app.route("/")
def home():
    return jsonify({"message": "ADACCSBI backend connected successfully!"})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    if not user.check_password(password):
        return jsonify({"error": "Invalid password"}), 401

    if user.status != "approved":
        return jsonify({"error": "User not approved"}), 403

    return jsonify({
        "message": "Login successful",
        "username": user.username,
        "role": user.role
    }), 200


@app.route("/admin-dashboard", methods=["GET"])
@role_required("admin")
def admin_dashboard():
    return jsonify({"message": "Welcome Admin!"})


@app.route("/employee-dashboard", methods=["GET"])
@role_required("employee")
def employee_dashboard():
    return jsonify({"message": "Welcome Employee!"})


# --------------------------
# Run App
# --------------------------

if __name__ == "__main__":
    with app.app_context():

        db.create_all()

        if not User.query.filter_by(username="admin").first():
            admin = User(
                username="admin",
                email="admin@adaccsbi.com",
                role="admin",
                status="approved"
            )
            admin.set_password("Admin123")
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully!")
        else:
            print("Admin already exists.")

    app.run(debug=True)
