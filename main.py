from flask import Flask, render_template, request, redirect, session
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Initialize SQLite DB
def init_db():
    with sqlite3.connect('users.db') as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL
                        )''')

# Hash passwords using SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Home redirects to login
@app.route('/')
def home():
    return redirect('/login')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = hash_password(request.form['password'])
        try:
            with sqlite3.connect('users.db') as conn:
                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            return redirect('/login')
        except sqlite3.IntegrityError:
            return "Username already exists!"
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hash_password(request.form['password'])
        with sqlite3.connect('users.db') as conn:
            user = conn.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password)).fetchone()
            if user:
                session['username'] = username
                return redirect('/chat')
            return "Invalid credentials"
    return render_template('login.html')

@app.route('/chat')
def chat():
    if 'username' in session:
        return render_template('chat.html', username=session['username'])
    return redirect('/login')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
