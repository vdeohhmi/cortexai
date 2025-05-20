import os
import csv
import uuid
from types import SimpleNamespace
from functools import wraps
from flask import (
    Flask, render_template, redirect, url_for,
    request, flash, session, send_file, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint, google
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer

# --- App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', uuid.uuid4().hex)

# Ensure instance folder exists for CSV storage
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE = os.path.join(BASE_DIR, 'instance')
os.makedirs(INSTANCE, exist_ok=True)

# --- CSV Helpers ---

def csv_path(filename):
    return os.path.join(INSTANCE, filename)

def read_csv(filename):
    """
    Read a CSV file into a list of dicts, cleaning up any extra columns.
    Discards any None keys from rows.
    """
    path = csv_path(filename)
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, newline='') as f:
        reader = csv.DictReader(f)
        for r in reader:
            # Remove any extra fields assigned to None key
            if None in r:
                r.pop(None)
            rows.append(r)
    return rows

def append_csv(filename, row):
    """
    Append a dict row to CSV, writing header if file is new.
    """
    path = csv_path(filename)
    file_exists = os.path.exists(path)
    with open(path, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

# --- Data Models ---
# CSV-backed storage
USER_FILE = 'users.csv'
COURSE_FILE = 'courses.csv'
ENROLL_FILE = 'enrollments.csv'
QUIZ_FILE = 'quizzes.csv'
RESULT_FILE = 'quiz_results.csv'

# User helpers
def read_users():
    return [SimpleNamespace(**u) for u in read_csv(USER_FILE)]

def find_user(username):
    return next((u for u in read_users() if u.username == username), None)

def create_user(username, password_hash, role):
    append_csv(USER_FILE, {'username': username, 'password_hash': password_hash, 'role': role})

# Course helpers
def read_courses():
    return [SimpleNamespace(**c) for c in read_csv(COURSE_FILE)]

def find_course(cid):
    return next((c for c in read_courses() if c.id == cid), None)

def create_course(id, title, description, educator, status):
    append_csv(COURSE_FILE, {
        'id': id, 'title': title,
        'description': description,
        'educator': educator, 'status': status
    })

# Enrollment helpers
def read_enrollments():
    return [SimpleNamespace(**e) for e in read_csv(ENROLL_FILE)]

def is_enrolled(username, course_id):
    return any(e for e in read_enrollments() if e.username == username and e.course_id == course_id)

def enroll_user(username, course_id):
    append_csv(ENROLL_FILE, {'username': username, 'course_id': course_id})

# Quiz helpers
def read_quizzes():
    return [SimpleNamespace(**q) for q in read_csv(QUIZ_FILE)]

def quizzes_for_course(course_id):
    return [q for q in read_quizzes() if q.course_id == course_id]

def create_quiz(id, course_id, question, options, answer):
    append_csv(QUIZ_FILE, {
        'id': id, 'course_id': course_id,
        'question': question, 'options': options, 'answer': answer
    })

# Result helpers
def read_results():
    return [SimpleNamespace(**r) for r in read_csv(RESULT_FILE)]

def results_for_user(username):
    return [r for r in read_results() if r.username == username]

def create_result(username, quiz_id, selected, correct):
    append_csv(RESULT_FILE, {
        'username': username,
        'quiz_id': quiz_id,
        'selected': selected,
        'correct': correct
    })

# --- OAuth & Email ---
# Google OAuth blueprint
google_bp = make_google_blueprint(
    client_id=os.environ.get('GOOGLE_OAUTH_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET'),
    scope=["profile", "email"],
    redirect_url="/login/google/authorized"
)
app.register_blueprint(google_bp, url_prefix="/login")

# Mail config
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD')
)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- Context & Auth Decorators ---
@app.context_processor
def inject_user():
    return dict(current_user=find_user(session.get('user')))

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('user'):
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

# --- Bootstrap Data ---
# Ensure default admin
if not find_user('admin'):
    create_user('admin', generate_password_hash('comp2801'), 'admin')
# Ensure sample courses
if not read_courses():
    sample = [
        ('1', 'Intro to AI', 'Learn the basics of AI'),
        ('2', 'Machine Learning', 'Hands-on ML algorithms')
    ]
    for cid, title, desc in sample:
        create_course(cid, title, desc, 'admin', 'active')

# --- Routes ---
@app.route('/')
@login_required
def catalog():
    courses = [c for c in read_courses() if c.status == 'active']
    return render_template('catalog.html', courses=courses)

@app.route('/course/<cid>')
@login_required
def course_detail(cid):
    course = find_course(cid)
    if not course:
        abort(404)
    enrolled = is_enrolled(session['user'], cid)
    return render_template('course_detail.html', course=course, enrolled=enrolled)

@app.route('/enroll/<cid>', methods=['POST'])
@login_required
def enroll(cid):
    if not is_enrolled(session['user'], cid):
        enroll_user(session['user'], cid)
        flash('Successfully enrolled!', 'success')
    return redirect(url_for('course_detail', cid=cid))

@app.route('/profile')
@login_required
def profile():
    user = find_user(session['user'])
    if user.role == 'student':
        all_courses = [c for c in read_courses() if c.status == 'active']
        enrolled = [c for c in all_courses if is_enrolled(user.username, c.id)]
        available = [c for c in all_courses if not is_enrolled(user.username, c.id)]
        return render_template('student_profile.html', user=user, enrolled=enrolled, available=available)
    if user.role == 'educator':
        own = [c for c in read_courses() if c.educator == user.username]
        return render_template('educator_profile.html', user=user, courses=own)
    return render_template('admin_dashboard.html')

@app.route('/educator/add_course', methods=['POST'])
@login_required
def educator_add_course():
    user = find_user(session['user'])
    if user.role != 'educator':
        abort(403)
    cid = str(uuid.uuid4())
    create_course(cid,
                  request.form['title'],
                  request.form['description'],
                  user.username,
                  'active')
    flash('Course created and active!', 'success')
    return redirect(url_for('profile'))

@app.route('/login/google/authorized')
def google_authorized():
    if not google.authorized:
        return redirect(url_for('login'))
    resp = google.get('/oauth2/v1/userinfo')
    if not resp.ok:
        flash('Google login failed.', 'danger')
        return redirect(url_for('login'))
    info = resp.json()
    email = info['email']
    user = find_user(email)
    if not user:
        create_user(email, generate_password_hash(uuid.uuid4().hex), 'student')
    session['user'] = email
    flash(f'Welcome, {email}!', 'success')
    return redirect(url_for('catalog'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        create_user(request.form['username'],
                    generate_password_hash(request.form['password']),
                    request.form['role'])
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', roles=['student', 'educator'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = find_user(request.form['username'])
        if user and check_password_hash(user.password_hash, request.form['password']):
            session['user'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('catalog'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/admin/courses', methods=['GET', 'POST'])
@login_required
def admin_courses():
    user = find_user(session['user'])
    if user.role != 'admin':
        abort(403)
    if request.method == 'POST':
        cid = str(uuid.uuid4())
        create_course(cid,
                      request.form['title'],
                      request.form['description'],
                      request.form['educator'],
                      'pending')
        flash('Course submitted for approval.', 'success')
    return render_template('admin_courses.html', courses=read_courses(), users=read_users())

@app.route('/admin/quizzes', methods=['GET', 'POST'])
@login_required
def admin_quizzes():
    user = find_user(session['user'])
    if user.role != 'admin':
        abort(403)
    if request.method == 'POST':
        qid = str(uuid.uuid4())
        create_quiz(qid,
                    request.form['course_id'],
                    request.form['question'],
                    request.form['options'],
                    request.form['answer'])
        flash('Quiz created!', 'success')
    return render_template('admin_quizzes.html', courses=read_courses(), quizzes=read_quizzes())

@app.route('/admin/export')
@login_required
def admin_export():
    user = find_user(session['user'])
    if user.role != 'admin':
        abort(403)
    return render_template('admin_export.html', files=['users','courses','enrollments','quizzes','quiz_results'])

@app.route('/admin/export/<name>')
@login_required
def download(name):
    user = find_user(session['user'])
    if user.role != 'admin':
        abort(403)
    path = csv_path(f"{name}.csv")
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=f"{name}.csv")

if __name__ == '__main__':
    app.run(debug=True)
