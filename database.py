from flask import Flask, request, render_template
import sqlite3

app = Flask(__name__)

@app.route('/')
def home():
    return "Welcome to the Security Demonstration"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print("Executing Query:", query)
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            return f"Welcome, {username}!"
        else:
            return "Invalid credentials!"

    return render_template('login.html')

if __name__ == "__main__":
    app.run(debug=True)
