from flask import Flask, render_template, request, redirect, session, url_for
import json
import os

app = Flask(__name__)
app.secret_key = 'super_secret_key'

DATA_DIR = 'data'
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
SCORES_FILE = os.path.join(DATA_DIR, 'scores.json')
CHALLENGES_FILE = os.path.join(DATA_DIR, 'challenges.json')

def load_json(path):
    with open(path, 'r') as f:
        return json.load(f)

def save_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        users = load_json(USERS_FILE)
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['user'] = username
            return redirect(url_for('dashboard'))
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    challenges = load_json(CHALLENGES_FILE)
    return render_template('dashboard.html', user=session['user'], challenges=challenges)

@app.route('/challenge/<id>', methods=['GET', 'POST'])
def challenge(id):
    if 'user' not in session:
        return redirect('/login')
    challenges = load_json(CHALLENGES_FILE)
    scores = load_json(SCORES_FILE)
    user = session['user']
    challenge = challenges.get(id)
    message = ''
    if request.method == 'POST':
        submitted_flag = request.form['flag'].strip()
        if submitted_flag == challenge['flag']:
            if user not in scores:
                scores[user] = 0
            scores[user] += challenge['points']
            save_json(SCORES_FILE, scores)
            message = 'Correct!'
        else:
            message = 'Wrong flag.'
    return render_template('challenge.html', challenge=challenge, message=message)

@app.route('/scoreboard')
def scoreboard():
    scores = load_json(SCORES_FILE)
    sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    return render_template('scoreboard.html', scores=sorted_scores)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
