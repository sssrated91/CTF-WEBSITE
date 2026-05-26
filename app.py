from flask import Flask, request, jsonify, session, send_from_directory
import sqlite3
import hashlib
import os
import re

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = 'ctf_secret_key_change_this_in_production'

DB_PATH = 'ctf_database.db'

# ─── DATABASE SETUP ───────────────────────────────────────────
def get_db():
    """Get a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create tables if they don't exist."""
    conn = get_db()
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Portfolio table — each row is one coin holding per user
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS portfolio (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            coin_id TEXT NOT NULL,
            coin_sym TEXT NOT NULL,
            coin_name TEXT NOT NULL,
            amount REAL NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, coin_id)
        )
    ''')

    conn.commit()
    conn.close()
    print("✅ Database ready.")

def hash_password(password):
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

# ─── SERVE PAGES ──────────────────────────────────────────────
@app.route('/')
def index():
    """Serve the login page by default."""
    return send_from_directory('templates', 'login.html')

@app.route('/app')
def main_app():
    """Serve the main CTF app (only if logged in)."""
    if 'user_id' not in session:
        return send_from_directory('templates', 'login.html')
    return send_from_directory('templates', 'index.html')

# ─── AUTH ROUTES ──────────────────────────────────────────────
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username', '').strip()
    email    = data.get('email', '').strip().lower()
    password = data.get('password', '')

    # Basic validation
    if not username or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required.'}), 400

    if len(username) < 3:
        return jsonify({'success': False, 'message': 'Username must be at least 3 characters.'}), 400

    if len(password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters.'}), 400

    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({'success': False, 'message': 'Please enter a valid email address.'}), 400

    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            (username, email, hash_password(password))
        )
        conn.commit()

        # Auto-login after signup
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        session['user_id']  = user['id']
        session['username'] = user['username']

        return jsonify({'success': True, 'username': username})

    except sqlite3.IntegrityError as e:
        if 'username' in str(e):
            return jsonify({'success': False, 'message': 'Username already taken.'}), 400
        if 'email' in str(e):
            return jsonify({'success': False, 'message': 'Email already registered.'}), 400
        return jsonify({'success': False, 'message': 'Account creation failed.'}), 400
    finally:
        conn.close()


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email    = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password are required.'}), 400

    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE email = ? AND password_hash = ?',
        (email, hash_password(password))
    ).fetchone()
    conn.close()

    if not user:
        return jsonify({'success': False, 'message': 'Incorrect email or password.'}), 401

    session['user_id']  = user['id']
    session['username'] = user['username']

    return jsonify({'success': True, 'username': user['username']})


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})


@app.route('/api/me', methods=['GET'])
def me():
    """Check if user is logged in."""
    if 'user_id' in session:
        return jsonify({'loggedIn': True, 'username': session['username']})
    return jsonify({'loggedIn': False})


# ─── PORTFOLIO ROUTES ─────────────────────────────────────────
@app.route('/api/portfolio', methods=['GET'])
def get_portfolio():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in.'}), 401

    conn = get_db()
    rows = conn.execute(
        'SELECT coin_id, coin_sym, coin_name, amount FROM portfolio WHERE user_id = ?',
        (session['user_id'],)
    ).fetchall()
    conn.close()

    portfolio = [{'id': r['coin_id'], 'sym': r['coin_sym'], 'name': r['coin_name'], 'amount': r['amount']} for r in rows]
    return jsonify({'success': True, 'portfolio': portfolio})


@app.route('/api/portfolio', methods=['POST'])
def save_portfolio():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in.'}), 401

    data     = request.get_json()
    coin_id  = data.get('id')
    coin_sym = data.get('sym')
    coin_name= data.get('name')
    amount   = data.get('amount')

    if not all([coin_id, coin_sym, coin_name, amount]):
        return jsonify({'success': False, 'message': 'Missing fields.'}), 400

    conn = get_db()
    try:
        # Insert or update (if coin already exists, add to amount)
        existing = conn.execute(
            'SELECT id, amount FROM portfolio WHERE user_id = ? AND coin_id = ?',
            (session['user_id'], coin_id)
        ).fetchone()

        if existing:
            conn.execute(
                'UPDATE portfolio SET amount = ? WHERE user_id = ? AND coin_id = ?',
                (existing['amount'] + amount, session['user_id'], coin_id)
            )
        else:
            conn.execute(
                'INSERT INTO portfolio (user_id, coin_id, coin_sym, coin_name, amount) VALUES (?, ?, ?, ?, ?)',
                (session['user_id'], coin_id, coin_sym, coin_name, amount)
            )
        conn.commit()
        return jsonify({'success': True})
    finally:
        conn.close()


@app.route('/api/portfolio/<coin_id>', methods=['DELETE'])
def delete_portfolio_coin(coin_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in.'}), 401

    conn = get_db()
    conn.execute(
        'DELETE FROM portfolio WHERE user_id = ? AND coin_id = ?',
        (session['user_id'], coin_id)
    )
    conn.commit()
    conn.close()
    return jsonify({'success': True})


# ─── RUN ──────────────────────────────────────────────────────
# Place this right ABOVE the 'if __name__ == "__main__":' block
# This ensures the database initializes whenever Flask starts up anywhere
init_db()

if __name__ == '__main__':
    print(" CTF server running at http://localhost:5000")
    app.run(debug=True, port=5000)