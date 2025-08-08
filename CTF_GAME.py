from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os
from datetime import datetime
from sqlalchemy.sql import func
from sqlalchemy import text
from flask_mail import Mail, Message
from dotenv import load_dotenv
from models import db, User, Challenge, Solve, AuditLog, Submission
import threading

load_dotenv()  # Load .env file

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or "supersecretkey"

# Enforce MySQL configuration only (per provided details)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://ctfuser:ctfpass123@localhost/ctfdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure Flask-Mail
app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT", 587))
app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS", "True") == "True"
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_USERNAME")

mail = Mail(app)

# Initialize database with app
db.init_app(app)

FERNET_KEY = b'DmxJF_crcWtbJwZw-cbz5LHKdr8oK8GwhociJmmL8ho='
fernet = Fernet(FERNET_KEY)

def trigger_export_async():
    """Kick off Excel export in the background; log errors without interrupting user flow."""
    try:
        from export_to_excel import export_all_to_excel
        threading.Thread(target=export_all_to_excel, daemon=True).start()
    except Exception as e:
        print(f"[EXPORT ERROR] Failed to start export thread: {e}")

def get_admin_email():
    """Return admin notification email from env or first admin user."""
    admin_email_env = os.getenv("ADMIN_EMAIL")
    if admin_email_env:
        return admin_email_env
    try:
        admin_user = User.query.filter_by(role='admin').first()
        if admin_user and admin_user.email:
            return admin_user.email
    except Exception:
        pass
    return None

def notify_admin(subject: str, body: str) -> None:
    """Send a notification email to the admin address if available."""
    admin_email = get_admin_email()
    if not admin_email:
        print(f"[ADMIN NOTIFY] No admin email configured. Subject: {subject}")
        return
    send_email(admin_email, subject, body)

def send_email(to_email, subject, body):
    try:
        msg = Message(subject, recipients=[to_email])
        msg.body = body
        # Mark emails as high priority
        try:
            msg.extra_headers = {
                'X-Priority': '1',
                'X-MSMail-Priority': 'High',
                'Importance': 'High',
            }
        except Exception:
            pass
        mail.send(msg)
        print(f"[EMAIL SENT] To: {to_email} | Subject: {subject}")
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send email to {to_email}: {e}")

# =================== ROUTES =====================

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password', '')
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for('signup'))
        if len(password) < 6:
            flash("Password must be at least 6 characters long", "error")
            return redirect(url_for('signup'))
        # Check if username or email already exists
        existing_user = User.query.filter((User.username == username)|(User.email == email)).first()
        if existing_user:
            flash("Username or email already exists", "error")
            return redirect(url_for('signup'))
        
        # If no existing user found, allow creation (this handles the case where user was previously deleted)
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()  # <-- ADD THIS LINE
        trigger_export_async()
        notify_admin(
            "New user signup",
            f"User '{new_user.username}' ({new_user.email}) has signed up."
        )
        send_email(new_user.email, "🎉 Welcome to the CTF Game!",
           f"Hello {new_user.username},\n\nYou're successfully signed up! Let's start solving challenges and capture the flags! 💥")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            # Send email on successful login only for non-admin users and only once
            if user.role != 'admin' and 'login_email_sent' not in session:
                send_email(
                    user.email,
                    "🔓 Login Successful - CTF Game",
                    f"Hello {user.username},\n\nYou have successfully logged in to the CTF platform."
                )
                # Mark that login email has been sent to prevent duplicates
                session['login_email_sent'] = True
            return redirect(url_for('dashboard'))
        flash("Invalid credentials", "error")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if user.role == 'admin':
        flash("Admins cannot play the game. You have access to admin controls only.", "info")
        return redirect(url_for('admin_panel'))
    db.session.refresh(user)  # Ensure latest score
    challenges = Challenge.query.all()
    solved_ids = {sub.challenge_id for sub in user.submissions if sub.correct}
    total_players = User.query.count()
    total_challenges = Challenge.query.count()
    total_solves = Solve.query.count() if 'Solve' in globals() else 0
    max_score = db.session.query(db.func.sum(Challenge.points)).scalar() or 0
    return render_template(
        'dashboard.html',
        username=user.username,
        challenges=challenges,
        solved_ids=solved_ids,
        total_players=total_players,
        total_challenges=total_challenges,
        total_solves=total_solves,
        user_score=user.score,
        last_updated=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

@app.route('/submit/<int:challenge_id>', methods=['POST'])
def submit_flag(challenge_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if user.role == 'admin':
        flash("Admins cannot submit flags.", "error")
        return redirect(url_for('admin_panel'))
    challenge = Challenge.query.get(challenge_id)
    if not challenge:
        flash('Challenge not found.', 'danger')
        return redirect(url_for('dashboard'))
    # Prevent double scoring for already-solved challenges
    already_solved = db.session.query(Solve.id).filter_by(user_id=user.id, challenge_id=challenge.id).first()
    if already_solved:
        flash('You have already solved this challenge. No additional points awarded.', 'info')
        return redirect(url_for('dashboard'))
    submitted_flag = request.form.get('flag')
    try:
        correct_flag = fernet.decrypt(challenge.flag_encrypted).decode()
        submission = Submission(user_id=user.id, challenge_id=challenge_id, submitted_flag=submitted_flag)
        if submitted_flag.strip() == correct_flag:
            submission.correct = True
            user.score += challenge.points
            db.session.add(Solve(user_id=user.id, challenge_id=challenge.id))
            flash(f'✅ Correct! You earned {challenge.points} points.', 'success')
            try:
                send_email(
                    user.email,
                    "✅ Challenge Solved!",
                    f"Great job {user.username}! You solved '{challenge.title}' and earned {challenge.points} points. Your new score is {user.score}."
                )
            except Exception:
                pass
            notify_admin(
                "Challenge solved",
                f"User '{user.username}' solved '{challenge.title}' for {challenge.points} points. New score: {user.score}."
            )
        else:
            submission.correct = False
            flash('❌ Incorrect flag. Try again or click "Show Answer".', 'danger')
        db.session.add(submission)
        db.session.commit()
        trigger_export_async()
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {e}', 'danger')
        return redirect(url_for('dashboard'))

    # Game completion check (move this inside the function)
    total_challenges = Challenge.query.count()
    solved_challenges = db.session.query(Solve).filter_by(user_id=user.id).count()
    if solved_challenges == total_challenges and total_challenges > 0 and user.role != 'admin':
        # Check if completion email has already been sent
        if 'completion_email_sent' not in session:
            send_email(user.email, "🏆 Congratulations on Completing the CTF!",
                       f"Great job, {user.username}!\n\nYou've completed all {total_challenges} challenges and scored {user.score} points.\n\nThanks for playing!")
            # Mark that completion email has been sent to prevent duplicates
            session['completion_email_sent'] = True
    return redirect(url_for('dashboard'))

@app.route('/show_answer/<int:challenge_id>')
def show_answer(challenge_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # Admins should not play
    if session.get('role') == 'admin':
        flash("Admins cannot view answers.", "error")
        return redirect(url_for('admin_panel'))
    challenge = Challenge.query.get(challenge_id)
    if not challenge:
        flash('Challenge not found.', 'danger')
        return redirect(url_for('dashboard'))
    answer = fernet.decrypt(challenge.flag_encrypted).decode()
    return render_template('show_answer.html', challenge=challenge, answer=answer)

@app.route('/scoreboard')
def scoreboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # Count only non-admin users for total players
    total_players = User.query.filter(User.role != 'admin').count()
    total_challenges = Challenge.query.count()
    total_solves = Solve.query.count()
    highest_score = db.session.query(func.sum(Challenge.points)).scalar() or 0

    # Get only non-admin users and their solve/score info
    scoreboard_data = (
        db.session.query(
            User.username,
            func.count(Solve.id).label('solve_count'),
            func.coalesce(func.sum(Challenge.points), 0).label('score')
        )
        .filter(User.role != 'admin')  # Exclude admin users
        .outerjoin(Solve, Solve.user_id == User.id)
        .outerjoin(Challenge, Challenge.id == Solve.challenge_id)
        .group_by(User.id)
        .order_by(func.coalesce(func.sum(Challenge.points), 0).desc(), User.username)
        .all()
    )

    return render_template(
        'scoreboard.html',
        results=scoreboard_data,
        total_players=total_players,
        total_challenges=total_challenges,
        total_solves=total_solves,
        highest_score=highest_score
    )

@app.route('/logout')
def logout():
    # Check if user is already logged out to prevent duplicate emails
    if 'user_id' in session and 'logout_email_sent' not in session:
        user = User.query.get(session['user_id'])
        # Only send logout email if not admin and email hasn't been sent
        if user and user.role != 'admin':
            send_email(
                user.email,
                "🚪 You have logged out - CTF Game",
                f"Hello {user.username},\n\nYou have logged out from the CTF platform.\nYour current score is: {user.score} points.\n\nSee you soon!"
            )
            # Mark that logout email has been sent to prevent duplicates
            session['logout_email_sent'] = True
    
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        flag = request.form['flag']
        points = int(request.form['points'])
        encrypted_flag = fernet.encrypt(flag.encode())
        challenge = Challenge(title=title, description=description, flag_encrypted=encrypted_flag, points=points)
        db.session.add(challenge)
        db.session.commit()
        trigger_export_async()
        notify_admin(
            "Challenge added",
            f"New challenge added by admin: '{title}' ({points} points)."
        )
        flash("Challenge added successfully.", "success")
    challenges = Challenge.query.all()
    users = User.query.all()
    return render_template('admin.html', challenges=challenges, users=users)

@app.route('/admin/delete/<int:challenge_id>', methods=['POST'])
def delete_challenge(challenge_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))
    try:
        challenge = Challenge.query.get_or_404(challenge_id)

        # Adjust user scores for those who solved this challenge (use grouped count to avoid loading all rows)
        solve_counts = (
            db.session.query(Solve.user_id, func.count(Solve.id))
            .filter(Solve.challenge_id == challenge_id)
            .group_by(Solve.user_id)
            .all()
        )
        for user_id, count in solve_counts:
            user = User.query.get(user_id)
            if user:
                user.score = max(0, user.score - (challenge.points * int(count)))

        # Delete child rows first using bulk deletes to satisfy FK constraints
        Submission.query.filter(Submission.challenge_id == challenge_id).delete(synchronize_session=False)
        Solve.query.filter(Solve.challenge_id == challenge_id).delete(synchronize_session=False)

        # Now delete the challenge itself
        db.session.delete(challenge)
        db.session.commit()
        trigger_export_async()
        notify_admin(
            "Challenge deleted",
            f"Challenge deleted by admin: '{challenge.title}' (id={challenge_id}). User scores adjusted accordingly."
        )
        flash("Challenge deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting challenge: {str(e)}", "error")
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))
    try:
        user = User.query.get_or_404(user_id)
        if user.role == 'admin':
            flash("Cannot delete admin user.", "error")
            return redirect(url_for('admin_panel'))

        # Delete dependent records to satisfy foreign key constraints
        user_solves = Solve.query.filter_by(user_id=user.id).all()
        for solve in user_solves:
            db.session.delete(solve)

        user_submissions = Submission.query.filter_by(user_id=user.id).all()
        for submission in user_submissions:
            db.session.delete(submission)

        db.session.delete(user)
        db.session.commit()
        trigger_export_async()
        notify_admin(
            "User deleted",
            f"Admin deleted user '{user.username}' (id={user.id})."
        )
        flash("User deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting user: {str(e)}", "error")
    return redirect(url_for('admin_panel'))

@app.route('/admin/edit/<int:challenge_id>', methods=['POST'])
def edit_challenge(challenge_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('login'))
    try:
        challenge = Challenge.query.get_or_404(challenge_id)
        challenge.title = request.form['edit_title']
        challenge.description = request.form['edit_description']
        challenge.points = int(request.form['edit_points'])
        
        # Update flag if provided
        if 'edit_flag' in request.form and request.form['edit_flag'].strip():
            new_flag = request.form['edit_flag'].strip()
            challenge.flag_encrypted = fernet.encrypt(new_flag.encode())
        
        db.session.commit()
        trigger_export_async()
        notify_admin(
            "Challenge updated",
            f"Challenge updated by admin: '{challenge.title}' (id={challenge.id})."
        )
        flash("Challenge updated successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating challenge: {str(e)}", "error")
    return redirect(url_for('admin_panel'))

@app.route('/admin/get_flag/<int:challenge_id>')
def get_challenge_flag(challenge_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized access'})
    try:
        challenge = Challenge.query.get_or_404(challenge_id)
        decrypted_flag = fernet.decrypt(challenge.flag_encrypted).decode()
        return jsonify({'success': True, 'flag': decrypted_flag})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == "__main__":
    # Ensure tables exist in the configured MySQL database
    with app.app_context():
        db.create_all()
    app.run(debug=True)