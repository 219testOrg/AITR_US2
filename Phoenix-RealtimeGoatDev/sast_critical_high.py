import os
import re
import pickle
import hashlib
import sqlite3
import subprocess
import logging
import random
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from xml.sax import make_parser
from flask import Flask, request, redirect, Response, render_template_string, make_response

app = Flask(__name__)
logger = logging.getLogger(__name__)
db_connection = None

DB_USER = "admin"
DB_PASSWORD = "SuperSecret123!"
API_KEY = "AKIAIOSFODNN7EXAMPLE"


# ============================================================
#  1. SQL Injection — string concatenation (CWE-89) [CRITICAL]
# ============================================================

@app.route("/user")
def get_user():
    uid = request.args.get("id", "")
    query = "SELECT * FROM users WHERE id = " + uid
    cursor = db_connection.cursor()
    cursor.execute(query)
    return Response(str(cursor.fetchall()), mimetype="text/plain")


# ============================================================
#  2. SQL Injection — f-string (CWE-89) [CRITICAL]
# ============================================================

@app.route("/search")
def search_users():
    keyword = request.args.get("q", "")
    cursor = db_connection.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{keyword}%'")
    return Response(str(cursor.fetchall()), mimetype="text/plain")


# ============================================================
#  3. SQL Injection — format() (CWE-89) [CRITICAL]
# ============================================================

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    query = "SELECT * FROM users WHERE name='{}' AND password='{}'".format(username, password)
    cursor = db_connection.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    if user:
        return Response("Authenticated", mimetype="text/plain")
    return Response("Access denied", status=401, mimetype="text/plain")


# ============================================================
#  4. OS Command Injection — shell=True (CWE-78) [CRITICAL]
# ============================================================

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return Response(output, mimetype="text/plain")


# ============================================================
#  5. OS Command Injection — os.system (CWE-78) [CRITICAL]
# ============================================================

@app.route("/dns")
def dns_lookup():
    domain = request.args.get("domain", "")
    os.system("nslookup " + domain)
    return Response("Lookup complete", mimetype="text/plain")


# ============================================================
#  6. OS Command Injection — os.popen (CWE-78) [CRITICAL]
# ============================================================

@app.route("/whois")
def whois():
    target = request.args.get("target", "")
    result = os.popen("whois " + target).read()
    return Response(result, mimetype="text/plain")


# ============================================================
#  7. Code Injection — eval() (CWE-94) [CRITICAL]
# ============================================================

@app.route("/calc")
def calculator():
    expr = request.args.get("expr", "0")
    result = eval(expr)
    return Response(str(result), mimetype="text/plain")


# ============================================================
#  8. Unsafe Deserialization — pickle (CWE-502) [CRITICAL]
# ============================================================

@app.route("/deserialize", methods=["POST"])
def deserialize():
    raw = request.get_data()
    obj = pickle.loads(raw)
    return Response(str(obj), mimetype="text/plain")


# ============================================================
#  9. Server-Side Template Injection (CWE-1336) [CRITICAL]
# ============================================================

@app.route("/welcome")
def welcome():
    name = request.args.get("name", "Guest")
    template = "<html><body><h1>Welcome, " + name + "!</h1>{{ config }}</body></html>"
    return render_template_string(template)


# ============================================================
# 10. XML External Entity — XXE (CWE-611) [CRITICAL]
# ============================================================

@app.route("/parse-xml", methods=["POST"])
def parse_xml():
    xml_data = request.get_data()
    parser = make_parser()
    parser.setFeature("http://xml.org/sax/features/external-general-entities", True)
    root = ET.fromstring(xml_data)
    return Response(ET.tostring(root, encoding="unicode"), mimetype="application/xml")


# ============================================================
# 11. Reflected XSS — direct echo (CWE-79) [HIGH]
# ============================================================

@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    html = "<html><body><h1>Hello, " + name + "!</h1></body></html>"
    return Response(html, mimetype="text/html")


# ============================================================
# 12. Stored XSS — database round-trip (CWE-79) [HIGH]
# ============================================================

comments_store = []

@app.route("/comment", methods=["POST"])
def add_comment():
    body = request.form.get("body", "")
    comments_store.append(body)
    return redirect("/comments")

@app.route("/comments")
def show_comments():
    page = "<html><body><h2>Comments</h2><ul>"
    for c in comments_store:
        page += "<li>" + c + "</li>"
    page += "</ul></body></html>"
    return Response(page, mimetype="text/html")


# ============================================================
# 13. Path Traversal — file read (CWE-22) [HIGH]
# ============================================================

@app.route("/read")
def read_file():
    filename = request.args.get("file", "")
    path = os.path.join("/uploads", filename)
    with open(path, "r") as f:
        return Response(f.read(), mimetype="text/plain")


# ============================================================
# 14. Path Traversal — file write (CWE-22) [HIGH]
# ============================================================

@app.route("/write", methods=["POST"])
def write_file():
    filename = request.form.get("file", "")
    content = request.form.get("content", "")
    path = "/uploads/" + filename
    with open(path, "w") as f:
        f.write(content)
    return Response("Written", mimetype="text/plain")


# ============================================================
# 15. SSRF — urllib (CWE-918) [HIGH]
# ============================================================

@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    resp = urllib.request.urlopen(url)
    return Response(resp.read(), mimetype="text/plain")


# ============================================================
# 16. Hardcoded Credentials (CWE-798) [HIGH]
# ============================================================

@app.route("/admin-panel")
def admin_panel():
    provided_pw = request.args.get("pw", "")
    if provided_pw == DB_PASSWORD:
        return Response("Admin access granted", mimetype="text/plain")
    return Response("Forbidden", status=403, mimetype="text/plain")


# ============================================================
# 17. Weak Hashing — MD5 for passwords (CWE-328) [HIGH]
# ============================================================

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    hashed = hashlib.md5(password.encode()).hexdigest()
    cursor = db_connection.cursor()
    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        (username, username + "@example.com", hashed),
    )
    db_connection.commit()
    return Response("User created", mimetype="text/plain")


# ============================================================
# 18. Log Injection (CWE-117) [HIGH]
# ============================================================

@app.route("/log-action")
def log_action():
    action = request.args.get("action", "")
    logger.info("User performed action: " + action)
    return Response("Logged", mimetype="text/plain")


# ============================================================
# 19. Insecure Randomness for token (CWE-330) [HIGH]
# ============================================================

@app.route("/token")
def generate_token():
    token = "".join([str(random.randint(0, 9)) for _ in range(32)])
    return Response(token, mimetype="text/plain")


# ============================================================
# 20. HTTP Response Splitting / Header Injection (CWE-113) [HIGH]
# ============================================================

@app.route("/set-locale")
def set_locale():
    lang = request.args.get("lang", "en")
    resp = make_response("Locale updated")
    resp.headers["Content-Language"] = lang
    return resp


# ========================  Init  =============================

def init_db():
    global db_connection
    db_connection = sqlite3.connect(":memory:", check_same_thread=False)
    cur = db_connection.cursor()
    cur.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password TEXT)"
    )
    cur.execute(
        "INSERT INTO users VALUES (1, 'admin', 'admin@test.com', 'e10adc3949ba59abbe56e057f20f883e')"
    )
    db_connection.commit()


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080, debug=True)
