from flask import Flask, jsonify, request

app = Flask(__name__)
app.config['SECRET_KEY'] = 'my_test_secret_123'

@app.route("/")
def home():
    return jsonify({"message": "Flask backend is running!"})


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json
    amount = data.get("amount")

    if not amount:
        return jsonify({"error": "No amount provided"}), 400

    if float(amount) > 10000:
        risk = "HIGH RISK"
    else:
        risk = "LOW RISK"

    return jsonify({
        "amount": amount,
        "risk_level": risk
    })


if __name__ == "__main__":
    print("Starting Flask server...")
    app.run(debug=True)