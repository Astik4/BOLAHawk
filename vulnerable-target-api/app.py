import os
from flask import Flask, jsonify
from models import db, User
from routes.auth import auth_bp
from routes.orders import orders_bp
from routes.admin import admin_bp
from seed_data import seed_db

app = Flask(__name__)
# Database file stored locally in the api directory
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'db.sqlite3')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(orders_bp)
app.register_blueprint(admin_bp)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "vulnerable-target-api is running"}), 200

@app.route('/api/seed', methods=['POST'])
def force_seed():
    seed_db()
    return jsonify({"message": "Database re-seeded successfully"}), 200

# Auto-initialize and seed DB if empty
with app.app_context():
    db.create_all()
    if User.query.first() is None:
        seed_db()

if __name__ == '__main__':
    # Run target API on port 5000.
    # debug mode is intentionally plantable via FLASK_DEBUG env var for local dev;
    # it is OFF by default (and off in Docker) since the Dockerfile uses CMD directly.
    _debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host='127.0.0.1', port=5000, debug=_debug)
