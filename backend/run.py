from flask import Flask
from app.routes import init_routes

app = Flask(__name__)
app.config['SECRET_KEY'] = 'my_test_secret_123'

# Initialize routes
init_routes(app)

if __name__ == "__main__":
    print("Starting Flask server...")  # debug print
    app.run(debug=True)