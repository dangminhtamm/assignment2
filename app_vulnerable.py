from flask import Flask, request, render_template, session
import sqlite3
import secrets
import bcrypt
import time

app = Flask(__name__)
app.secret_key = 'supersecretkey'


def generate_csrf_token():
    token = secrets.token_hex(16)
    session['_csrf_token'] = token
    return token


def validate_csrf_token():
    token = request.form.get('_csrf_token')
    if not token or token != session.get('_csrf_token'):
        return False
    return True


def initialize_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)''')
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', ?)",
                   (bcrypt.hashpw('password123'.encode('utf-8'), bcrypt.gensalt()),))
    conn.commit()
    conn.close()

    conn = sqlite3.connect('comments.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS comments (comment TEXT)''')
    conn.commit()
    conn.close()


initialize_db()

failed_attempts = {}
BLOCK_TIME = 30
ATTEMPT_LIMIT = 5


@app.route('/')
def home():
    return """
    <h1>Welcome to the Vulnerable App</h1>
    <p>Available routes:</p>
    <ul>
        <li><a href="/sql_injection">SQL Injection Demo</a></li>
        <li><a href="/xss">XSS Demo</a></li>
        <li><a href="/vulnerable_bruteforce">Brute Force Demo</a></li>
        <li><a href="/vulnerable_clickjacking">Clickjacking Demo</a></li>
    </ul>
    """


@app.route('/sql_injection', methods=['GET', 'POST'])
def vulnerable_sql_injection():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print("Executing Query:", query)
        user = cursor.fetchone()
        conn.close()

        if user:
            return f"Welcome, {username}! (Vulnerable to SQL Injection)"
        else:
            return "Invalid credentials! (SQL Injection Vulnerable Login)"

    return render_template('login.html')


@app.route('/xss', methods=['GET', 'POST'])
def vulnerable_xss():
    if request.method == 'POST':
        comment = request.form['comment']

        conn = sqlite3.connect('comments.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO comments (comment) VALUES (?)", (comment,))
        conn.commit()
        conn.close()

        return "Comment submitted! (Vulnerable to XSS)"

    conn = sqlite3.connect('comments.db')
    cursor = conn.cursor()
    cursor.execute("SELECT comment FROM comments")
    comments = cursor.fetchall()
    conn.close()

    return render_template('welcome.html', comments=comments)


@app.route('/vulnerable_clickjacking')
def vulnerable_clickjacking():
    return render_template('vulnerable_clickjacking.html')


@app.route('/vulnerable_bruteforce', methods=['GET', 'POST'])
def vulnerable_bruteforce():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        client_ip = request.remote_addr

        if client_ip in failed_attempts:
            attempts, block_start = failed_attempts[client_ip]
            if attempts >= ATTEMPT_LIMIT:
                if time.time() - block_start < BLOCK_TIME:
                    return "Too many failed attempts. Try again later."
                else:
                    del failed_attempts[client_ip]

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            if client_ip in failed_attempts:
                del failed_attempts[client_ip]
            return f"Welcome, {username}! (Vulnerable to Brute Force)"
        else:
            if client_ip not in failed_attempts:
                failed_attempts[client_ip] = (1, time.time())
            else:
                attempts, block_start = failed_attempts[client_ip]
                failed_attempts[client_ip] = (attempts + 1, block_start)
            return "Invalid credentials! (Brute Force Vulnerable Login)"

    return render_template('bruteforce_login.html')


if __name__ == "__main__":
    app.run(debug=True)
