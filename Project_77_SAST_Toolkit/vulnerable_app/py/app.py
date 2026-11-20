import os, sqlite3, subprocess
from flask import Flask, request

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hardcoded_secret_key_123'
app.config['DEBUG'] = True

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
API_KEY = "sk-1234567890abcdef"
DB_PASSWORD = "admin123"

@app.route('/user')
def get_user():
    uid = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE id=" + uid
    cur.execute(query)
    return str(cur.fetchall())

@app.route('/search')
def search():
    term = request.args.get('q')
    return f"<div>{term}</div>"

def run_cmd():
    cmd = input("cmd: ")
    os.system(cmd)

def unsafe_eval(code):
    return eval(code)

def fetch_url(url):
    import requests
    return requests.get(url, verify=False)
