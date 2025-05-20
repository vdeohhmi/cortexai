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
if not os.path.isdir(INSTANCE):
    os.makedirs(INSTANCE, exist_ok=True)

# --- CSV Helpers ---
def csv_path(filename):
    return os.path.join(INSTANCE, filename)

def read_csv(filename):
    path = csv_path(filename)
    if not os.path.exists(path):
        return []
    with open(path, newline='') as f:
        reader = csv.DictReader(f)
        rows = []
        for r in reader:
            if None in r:
                r.pop(None)
            rows.append(r)
        return rows

def append_csv(filename, row):
    path = csv_path(filename)
    exists = os.path.exists(path)
    with open(path, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if not exists:
            writer.writeheader()
        writer.writerow(row)

# --- Data Files ---
USER_FILE = 'users.csv'
COURSE_FILE = 'courses.csv'
ENROLL_FILE = 'enrollments.csv'
QUIZ_FILE = 'quizzes.csv'
RESULT_FILE = 'quiz_results.csv'

# --- Model Helpers ---
def read_users():
    return [SimpleNamespace(**u) for u in read_csv(USER_FILE)]

def find_user(username):
    return next((u for u in read_users() if u.username == username), None)

def create_user(username, password_hash, role):
    append_csv(USER_FILE, {'username': username, 'password_hash': password_hash, 'role': role})


def read_courses():
    rows = read_csv(COURSE_FILE)
    for r in rows:
        if 'status' not in r or not r['status']:
            r['status'] = 'active'
    return [SimpleNamespace(**c) for c in rows]

def find_course(course_id):
    return next((c for c in read_courses() if c.id == course_id), None)

def create_course(cid, title, desc, educator, status):
    append_csv(COURSE_FILE, {
        'id': cid,
        'title': title,
        'description': desc,
        'educator': educator,
        'status': status
    })


def read_enrollments():
    return [SimpleNamespace(**e) for e in read_csv(ENROLL_FILE)]

def is_enrolled(username, cid):
    return any(e for e in read_enrollments() if e.username == username and e.course_id == cid)

def enroll_user(username, cid):
    append_csv(ENROLL_FILE, {'username': username, 'course_id': cid})


def read_quizzes():
    return [SimpleNamespace(**q) for q in read_csv(QUIZ_FILE)]

def quizzes_for_course(cid):
    return [q for q in read_quizzes() if q.course_id == cid]

def create_quiz(qid, cid, question, options, answer):
    append_csv(QUIZ_FILE, {
        'id': qid,
        'course_id': cid,
        'question': question,
        'options': options,
        'answer': answer
    })


def read_results():
    return [SimpleNamespace(**r) for r in read_csv(RESULT_FILE)]

def results_for_user(username):
    return [r for r in read_results() if r.username == username]

def create_result(username, qid, selected, correct):
    append_csv(RESULT_FILE, {
        'username': username,
        'quiz_id': qid,
        'selected': selected,
        'correct': correct
    })

# --- OAuth & Email Config ---
google_bp = make_google_blueprint(
    client_id=os.environ.get('GOOGLE_OAUTH_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET'),
    scope=["profile", "email"],
    redirect_url="/login/google/authorized"
)
app.register_blueprint(google_bp, url_prefix="/login")
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD')
)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- Template Context & Auth Decorator ---
@app.context_processor

def inject_helpers():
    return {
        'current_user': find_user(session.get('user')),
        'find_user': find_user,
        'read_courses': read_courses,
        'read_quizzes': read_quizzes
    }

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# --- Bootstrap Default Data ---
if not find_user('admin'):
    create_user('admin', generate_password_hash('comp2801'), 'admin')
if not read_courses():
    default_courses = [
        ('1', 'Intro to AI', 'Learn AI basics'),
        ('2', 'Machine Learning', 'Explore ML algorithms')
    ]
    for cid, title, desc in default_courses:
        create_course(cid, title, desc, 'admin', 'active')

# --- Routes ---
@app.route('/')
@login_required
def catalog():
    courses = [c for c in read_courses() if c.status == 'active']
    return render_template('catalog.html', courses=courses)

@app.route('/course/<course_id>')
@login_required
def course_detail(course_id):
    course = find_course(course_id)
    if not course:
        abort(404)
    return render_template(
        'course_detail.html',
        course=course,
        enrolled=is_enrolled(session['user'], course_id)
    )

@app.route('/enroll/<course_id>', methods=['POST'])
@login_required
def enroll(course_id):
    if not is_enrolled(session['user'], course_id):
        enroll_user(session['user'], course_id)
        flash('Enrolled successfully!', 'success')
    return redirect(url_for('course_detail', course_id=course_id))

@app.route('/lesson/<course_id>')
@login_required
def lesson(course_id):
    if not is_enrolled(session['user'], course_id):
        abort(403)
    course = find_course(course_id)
    return render_template('lesson.html', course=course)

@app.route('/quiz/<course_id>', methods=['GET', 'POST'])
@login_required
def take_quiz(course_id):
    quizzes = quizzes_for_course(course_id)
    if request.method == 'POST':
        score = 0
        for q in quizzes:
            sel = request.form.get(q.id)
            correct = q.answer
            create_result(session['user'], q.id, sel, correct)
            if sel == correct:
                score += 1
        return render_template('quiz_result.html', score=score, total=len(quizzes))
    return render_template('take_quiz.html', quizzes=quizzes)

@app.route('/profile')
@login_required
def profile():
    user = find_user(session['user'])
    if user.role == 'student':
        active = [c for c in read_courses() if c.status == 'active']
        enrolled = [c for c in active if is_enrolled(user.username, c.id)]
        available = [c for c in active if not is_enrolled(user.username, c.id)]
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
    create_course(
        cid,
        request.form['title'],
        request.form['description'],
        user.username,
        'active'
    )
    flash('Course created!', 'success')
    return redirect(url_for('profile'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Google OAuth completion
    if google.authorized:
        resp = google.get('/oauth2/v1/userinfo')
        if resp.ok:
            email = resp.json().get('email')
            if not find_user(email):
                create_user(email, generate_password_hash(uuid.uuid4().hex), 'student')
            session['user'] = email
            flash('Logged in via Google', 'success')
            return redirect(url_for('catalog'))
        flash('Google login failed', 'danger')
        return redirect(url_for('login'))
    # Username/password login
    if request.method == 'POST':
        user = find_user(request.form['username'])
        if user and check_password_hash(user.password_hash, request.form['password']):
            session['user'] = user.username
            flash('Login successful', 'success')
            return redirect(url_for('catalog'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('login'))

@app.route('/login/google')
def google_login():
    return redirect(url_for('google.login'))

@app.route('/login/google/authorized')
def google_authorized():
    # Handled above in /login
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        create_user(
            request.form['username'],
            generate_password_hash(request.form['password']),
            request.form['role']
        )
        flash('Registered successfully', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', roles=['student', 'educator'])

@app.route('/admin/courses', methods=['GET', 'POST'])
@login_required
def admin_courses():
    user = find_user(session['user'])
    if user.role != 'admin':
        abort(403)
    if request.method == 'POST':
        create_course(
            str(uuid.uuid4()),
            request.form['title'],
            request.form['description'],
            request.form['educator'],
            'pending'
        )
        flash('Course submitted for approval', 'success')
    return render_template('admin_courses.html', courses=read_courses(), users=read_users())

@app.route('/admin/quizzes', methods=['GET', 'POST'])
@login_required
def admin_quizzes():
    user = find_user(session['user'])
    if user.role != 'admin':
        abort(403)
    if request.method == 'POST':
        create_quiz(
            str(uuid.uuid4()),
            request.form['course_id'],
            request.form['question'],
            request.form['options'],
            request.form['answer']
        )
        flash('Quiz created', 'success')
    return render_template('admin_quizzes.html', courses=read_courses(), quizzes=read_quizzes())

@app.route('/admin/export')
@login_required
def admin_export():
    user = find_user(session['user'])
    if user.role != 'admin':
        abort(403)
    files = ['users', 'courses', 'enrollments', 'quizzes', 'quiz_results']
    return render_template('admin_export.html', files=files)

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
