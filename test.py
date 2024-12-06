import unittest
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from collections import defaultdict

app = Flask(__name__)

# In-memory rate limiter store (you could use a Redis or in-memory dict in production)
request_times = defaultdict(list)
MAX_REQUESTS = 5  # Allow max 5 requests within the last 60 seconds

# Rate limiter logic
def is_rate_limited(user_id):
    """Check if a user is rate-limited (more than MAX_REQUESTS in 60 seconds)."""
    now = datetime.utcnow()
    # Keep only requests from the last 60 seconds
    request_times[user_id] = [t for t in request_times[user_id] if (now - t).total_seconds() < 60]
    if len(request_times[user_id]) >= MAX_REQUESTS:
        return True
    # Log the current request time
    request_times[user_id].append(now)
    return False

@app.route('/auth', methods=['POST'])
def auth():
    user_id = request.json.get('user_id')
    if is_rate_limited(user_id):
        return jsonify({"message": "Rate limit exceeded"}), 429
    # Simulate an actual authentication process
    return jsonify({"message": "Authenticated"}), 200

class TestRateLimiter(unittest.TestCase):
    def setUp(self):
        """Setup test environment, including an in-memory database and Flask test client."""
        self.db_conn = sqlite3.connect(":memory:")  # Use an in-memory SQLite database
        self.cursor = self.db_conn.cursor()
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS users(
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                username TEXT NOT NULL,
                                password TEXT NOT NULL)''')
        self.db_conn.commit()
        
        self.client = app.test_client()  # Flask test client for simulating requests

    def tearDown(self):
        """Tear down test environment."""
        self.cursor.close()
        self.db_conn.close()

    def test_rate_limit(self):
        """Test if the rate limiter works by sending more than the allowed requests."""
        user_id = 1
        # Send 5 requests within 60 seconds (these should succeed)
        for i in range(5):
            response = self.client.post('/auth', json={'user_id': user_id})
            print(f"Request {i+1}: Status code {response.status_code}, Response body: {response.get_json()}")
            self.assertEqual(response.status_code, 200)

        # Send the 6th request, which should trigger rate limiting
        response = self.client.post('/auth', json={'user_id': user_id})
        print(f"6th Request: Status code {response.status_code}, Response body: {response.get_json()}")
        self.assertEqual(response.status_code, 429)  # Expecting rate limit exceeded
        self.assertEqual(response.get_json()['message'], "Rate limit exceeded")

    def test_register_user(self):
        """Test user registration."""
        username = "test_user"
        password = "secure_password"
        self.cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        self.db_conn.commit()
        self.cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        user = self.cursor.fetchone()
        self.assertIsNotNone(user)
        self.assertEqual(user[1], username)

if __name__ == '__main__':
    unittest.main()
