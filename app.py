from flask import Flask, render_template_string, request, redirect, url_for, session
import re
from flask import Flask, render_template_string, request, redirect, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import re
from urllib.parse import urlparse
import os


app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

DATABASE = 'phishing_checker.db'

PHISHING_KEYWORDS = [
    "login", "verify", "update", "secure", "banking", "account",
    "paypal", "ebay", "confirm", "webscr", "signin", "security"
]

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
@app.route('/initdb')
def initialize():
    init_db()
    return "Database initialized!"
def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS url_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                url TEXT NOT NULL,
                result TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        db.commit()

def is_phishing_url(url):
    url = url.lower()
    if any(keyword in url for keyword in PHISHING_KEYWORDS):
        return True
    # Simple heuristic for IP address in URL
    if re.match(r'^http[s]?://\d{1,3}(\.\d{1,3}){3}', url):
        return True
    # @ symbol phishing trick
    if '@' in url:
        return True
    # Suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
    if any(tld in url for tld in suspicious_tlds):
        return True
    # Too many subdomains
    domain_parts = urlparse(url).netloc.split('.')
    if len(domain_parts) > 3:
        return True
    return False

HEADER_FOOTER = """
<header class="bg-primary text-white text-center p-4 mb-4">
    <img src="https://images.unsplash.com/photo-1504384308090-c894fdcc538d?auto=format&fit=crop&w=40&q=80" alt="Logo" class="rounded-circle" style="height:40px; margin-right:10px;">
    <span class="h3">Phishing URL Checker</span>
</header>
<footer class="bg-dark text-white text-center p-3 mt-5">
    <p>© 2025 Phishing URL Checker &nbsp;|&nbsp; <a href="#" class="text-white">Privacy Policy</a></p>
    <img src="https://images.unsplash.com/photo-1515377905703-c4788e51af15?auto=format&fit=crop&w=40&q=80" alt="Footer Image" class="rounded-circle" style="height:40px;">
</footer>
"""

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Login - Phishing URL Checker</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
</head>
<body>
  {{ header_footer|safe }}
  <div class="container d-flex flex-column align-items-center justify-content-center" style="min-height: 70vh;">
    <div class="card p-4 shadow" style="max-width: 400px; width: 100%;">
      <h2 class="text-center mb-4">Login</h2>
      {% if error %}<div class="alert alert-danger">{{ error }}</div>{% endif %}
      <form method="post">
        <div class="mb-3">
          <label for="username" class="form-label">Username</label>
          <input class="form-control" type="text" id="username" name="username" required autofocus>
        </div>
        <div class="mb-3">
          <label for="password" class="form-label">Password</label>
          <input class="form-control" type="password" id="password" name="password" required>
        </div>
        <button class="btn btn-primary w-100" type="submit">Login</button>
      </form>
      <p class="mt-3 text-center">Don't have an account? <a href="{{ url_for('signup') }}">Sign up</a></p>
    </div>
  </div>
  {{ footer|safe }}
</body>
</html>
"""

SIGNUP_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Sign Up - Phishing URL Checker</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
</head>
<body>
  {{ header_footer|safe }}
  <div class="container d-flex flex-column align-items-center justify-content-center" style="min-height: 70vh;">
    <div class="card p-4 shadow" style="max-width: 400px; width: 100%;">
      <h2 class="text-center mb-4">Sign Up</h2>
      {% if error %}<div class="alert alert-danger">{{ error }}</div>{% endif %}
      <form method="post">
        <div class="mb-3">
          <label for="username" class="form-label">Username</label>
          <input class="form-control" type="text" id="username" name="username" required autofocus>
        </div>
        <div class="mb-3">
          <label for="password" class="form-label">Password</label>
          <input class="form-control" type="password" id="password" name="password" required>
        </div>
        <button class="btn btn-success w-100" type="submit">Sign Up</button>
      </form>
      <p class="mt-3 text-center">Already have an account? <a href="{{ url_for('login') }}">Login</a></p>
    </div>
  </div>
  {{ footer|safe }}
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Dashboard - Phishing URL Checker</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
  <style>
    body { background-color: #f0f2f5; }
    .result-legit { color: green; font-weight: 600; }
    .result-phishing { color: red; font-weight: 600; }
  </style>
</head>
<body>
  {{ header_footer|safe }}
  <div class="container mt-4">
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h2>Welcome, {{ username }}!</h2>
      <form method="post" action="{{ url_for('logout') }}">
        <button class="btn btn-danger" type="submit">Logout</button>
      </form>
    </div>

    <div class="card p-4 mb-4 shadow">
      <h4>Check a URL</h4>
      <form method="post">
        <div class="input-group mb-3">
          <input
            type="text"
            class="form-control"
            name="url"
            placeholder="Enter a URL to check"
            required
          />
          <button class="btn btn-primary" type="submit">Check URL</button>
        </div>
      </form>
      {% if result %}
        <div class="alert {{ 'alert-danger' if result == 'Phishing URL Detected' else 'alert-success' }}">
          {{ result }}
        </div>
      {% endif %}
    </div>

    <div class="card p-4 shadow">
      <h4>Your URL Check History</h4>
      {% if history %}
        <table class="table table-striped">
          <thead>
            <tr>
              <th>#</th>
              <th>URL</th>
              <th>Result</th>
              <th>Checked At</th>
            </tr>
          </thead>
          <tbody>
            {% for entry in history %}
              <tr>
                <td>{{ loop.index }}</td>
                <td><a href="{{ entry['url'] }}" target="_blank">{{ entry['url'] }}</a></td>
                <td class="{{ 'result-phishing' if entry['result']=='Phishing URL Detected' else 'result-legit' }}">
                  {{ entry['result'] }}
                </td>
                <td>{{ entry['timestamp'] }}</td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      {% else %}
        <p>No URL checks yet.</p>
      {% endif %}
    </div>
  </div>
  {{ footer|safe }}
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    user_id = session['user_id']
    username = session['username']
    result = None

    if request.method == 'POST':
        url = request.form['url'].strip()
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'http://' + url  # Default to http
        if not re.match(r'^https?://', url):
            result = "Invalid URL format."
        else:
            phishing = is_phishing_url(url)
            result = "Phishing URL Detected" if phishing else "Legitimate URL"

            # Save to DB
            db.execute(
                'INSERT INTO url_checks (user_id, url, result) VALUES (?, ?, ?)',
                (user_id, url, result)
            )
            db.commit()

    history = db.execute(
        'SELECT url, result, timestamp FROM url_checks WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10',
        (user_id,)
    ).fetchall()

    return render_template_string(DASHBOARD_TEMPLATE,
                                  username=username,
                                  result=result,
                                  history=history,
                                  header_footer=HEADER_FOOTER,
                                  footer='')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))
        else:
            error = "Invalid username or password."
    return render_template_string(LOGIN_TEMPLATE, error=error, header_footer=HEADER_FOOTER, footer='')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if len(username) < 3 or len(password) < 6:
            error = "Username must be at least 3 chars; password at least 6 chars."
        else:
            db = get_db()
            existing = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if existing:
                error = "Username already taken."
            else:
                hashed_password = generate_password_hash(password)
                db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
                db.commit()
                return redirect(url_for('login'))
    return render_template_string(SIGNUP_TEMPLATE, error=error, header_footer=HEADER_FOOTER, footer='')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))

def is_phishing_url(url):
    url = url.lower()
    
    # Keyword match
    if any(keyword in url for keyword in PHISHING_KEYWORDS):
        return True

    # Check for use of IP address instead of domain
    if re.match(r'^http[s]?://\d{1,3}(\.\d{1,3}){3}', url):
        return True

    # Check for use of '@' symbol
    if '@' in url:
        return True

    # Check for suspicious TLDs
    if any(tld in url for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']):
        return True

    # Check for multiple subdomains (e.g., login.secure.paypal.com.phishing.site)
    domain_parts = urlparse(url).netloc.split('.')
    if len(domain_parts) > 3:
        return True

    return False

    url = url.lower()
    
    # Keyword match
    if any(keyword in url for keyword in PHISHING_KEYWORDS):
        return True

    # Check for use of IP address instead of domain
    if re.match(r'^http[s]?://\d{1,3}(\.\d{1,3}){3}', url):
        return True

    # Check for use of '@' symbol
    if '@' in url:
        return True

    # Check for suspicious TLDs
    if any(tld in url for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']):
        return True

    # Check for multiple subdomains (e.g., login.secure.paypal.com.phishing.site)
    domain_parts = urlparse(url).netloc.split('.')
    if len(domain_parts) > 3:
        return True

    return False

    url = url.lower()
    
    # Check for phishing keywords
    if any(keyword in url for keyword in PHISHING_KEYWORDS):
        return True

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    ext = tldextract.extract(url)

    # Check if domain is an IP address
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        pass

    # Check for suspicious TLDs
    if ext.suffix in ['tk', 'ml', 'ga', 'cf', 'gq']:
        return True

    # Check for too many subdomains
    if len(ext.subdomain.split('.')) > 2:
        return True

    # Check for @ symbol
    if '@' in url:
        return True

    return False

    url = url.lower()
    return any(keyword in url for keyword in PHISHING_KEYWORDS)

if __name__ == '__main__':
    with app.app_context():
        init_db()   # <-- This creates your tables if not exist
    app.run(debug=True)
