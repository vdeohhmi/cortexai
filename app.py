import os
import csv
import uuid
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
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev')

top = os.path.dirname(__file__)
# Ensure storage directory for CSVs
os.makedirs(os.path.join(top, 'instance'), exist_ok=True)

# --- CSV Helpers ---
def csv_path(filename):
    return os.path.join(top, 'instance', filename)

def read_csv(name, fields):
    path = csv_path(name)
    rows = []
    if os.path.exists(path):
        with open(path, newline='') as f:
            reader = csv.DictReader(f, fieldnames=fields)
            next(reader, None)  # skip header row
            for r in reader:
                rows.append(r)
    return rows

def append_csv(name, row, fields):
    path = csv_path(name)
    exists = os.path.exists(path)
    with open(path, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        if not exists:
            writer.writeheader()
        writer.writerow(row)

# --- Models ---
USER_FIELDS = ['username', 'password_hash', 'role']
COURSE_FIELDS = ['id', 'title', 'description', 'educator', 'status']
ENROLL_FIELDS = ['username', 'course_id']
QUIZ_FIELDS = ['id', 'course_id', 'question', 'options', 'answer']
RESULT_FIELDS = ['username', 'quiz_id', 'selected', 'correct']

# User functions
def read_users():    return read_csv('users.csv', USER_FIELDS)

def write_user(u, ph, r):
    append_csv('users.csv', {'username': u, 'password_hash': ph, 'role': r}, USER_FIELDS)

def find_user(u):
    return next((x for x in read_users() if x['username'] == u), None)

# Course functions
def read_courses(): return read_csv('courses.csv', COURSE_FIELDS)

def write_course(c): append_csv('courses.csv', c, COURSE_FIELDS)

def find_course(cid):
    return next((c for c in read_courses() if c['id'] == cid), None)

# Enrollment
def read_enroll(): return read_csv('enrollments.csv', ENROLL_FIELDS)

def enroll_user(u, cid):
    append_csv('enrollments.csv', {'username': u, 'course_id': cid}, ENROLL_FIELDS)

def is_enrolled(u, cid):
    return any(e for e in read_enroll() if e['username'] == u and e['course_id'] == cid)

# Quiz functions
def read_quizzes(): return read_csv('quizzes.csv', QUIZ_FIELDS)

def write_quiz(q): append_csv('quizzes.csv', q, QUIZ_FIELDS)

def course_quizzes(cid):
    return [q for q in read_quizzes() if q['course_id'] == cid]

# Quiz results
def user_results(u):
    return [r for r in read_csv('quiz_results.csv', RESULT_FIELDS) if r['username'] == u]

def write_result(r): append_csv('quiz_results.csv', r, RESULT_FIELDS)

# --- OAuth & Mail Setup ---
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

# --- Template Context ---
@app.context_processor
def inject_utils():
    return {
        'find_user': find_user,
        'read_courses': read_courses,
        'read_quizzes': read_quizzes
    }

# --- Auth Decorator ---
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# --- Bootstrap Default Data ---
if not find_user('admin'):
    write_user('admin', generate_password_hash('comp2801'), 'admin')
if not read_courses():
    defaults = [
        {'id': '1', 'title': 'Intro to AI',         'description': 'Basics of AI',    'educator': 'admin', 'status': 'active'},
        {'id': '2', 'title': 'Machine Learning',    'description': 'ML algorithms',  'educator': 'admin', 'status': 'active'}
    ]
    for c in defaults:
        write_course(c)

# --- Routes ---
@app.route('/')
@login_required
def catalog():
    # Show only active courses
    courses = [c for c in read_courses() if c.get('status') == 'active']
    return render_template('catalog.html', courses=courses)

@app.route('/course/<cid>')
@login_required
def course_detail(cid):
    course = find_course(cid)
    if not course:
        abort(404)
    enrolled = is_enrolled(session['user'], cid)
    return render_template('course_detail.html', course=course, enrolled=enrolled)

@app.route('/enroll/<cid>')
@login_required
def enroll(cid):
    if not is_enrolled(session['user'], cid):
        enroll_user(session['user'], cid)
        flash('Enrolled in course!', 'success')
    return redirect(url_for('course_detail', cid=cid))

@app.route('/profile')
@login_required
def profile():
    u = find_user(session['user'])
    if u['role'] == 'student':
        all_active = [c for c in read_courses() if c.get('status') == 'active']
        enrolled = [c for c in all_active if is_enrolled(u['username'], c['id'])]
        available = [c for c in all_active if not is_enrolled(u['username'], c['id'])]
        return render_template('student_profile.html', user=u, enrolled=enrolled, available=available)
    elif u['role'] == 'educator':
        own = [c for c in read_courses() if c.get('educator') == u['username']]
        return render_template('educator_profile.html', user=u, courses=own)
    else:
        return render_template('admin_dashboard.html')

@app.route('/educator/add_course', methods=['POST'])
@login_required
def educator_add_course():
    u = find_user(session['user'])
    if u['role'] != 'educator':
        abort(403)
    new_id = str(uuid.uuid4())
    write_course({
        'id': new_id,
        'title': request.form['title'],
        'description': request.form['description'],
        'educator': u['username'],
        'status': 'active'
    })
    flash('Course created successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/login/google/authorized')
def google_authorized():
    if not google.authorized:
        return redirect(url_for('login'))
    resp = google.get('/oauth2/v1/userinfo')
    if not resp.ok:
        flash('Failed Google login.', 'danger')
        return redirect(url_for('login'))
    info = resp.json()
    email = info.get('email')
    user = find_user(email)
    if not user:
        write_user(email, generate_password_hash(uuid.uuid4().hex), 'student')
    session['user'] = email
    flash(f'Welcome, {email}!', 'success')
    return redirect(url_for('catalog'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        write_user(request.form['username'],
                   generate_password_hash(request.form['password']),
                   request.form['role'])
        flash('Registered successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', roles=['student', 'educator'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = find_user(request.form['username'])
        if u and check_password_hash(u['password_hash'], request.form['password']):
            session['user'] = u['username']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('catalog'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/admin/courses', methods=['GET', 'POST'])
@login_required
def admin_courses():
    u = find_user(session['user'])
    if u['role'] != 'admin':
        abort(403)
    if request.method == 'POST':
        new_id = str(uuid.uuid4())
        write_course({
            'id': new_id,
            'title': request.form['title'],
            'description': request.form['description'],
            'educator': request.form['educator'],
            'status': 'pending'
        })
        flash('Course added for review.', 'success')
    return render_template('admin_courses.html', courses=read_courses(), users=read_users())

@app.route('/admin/quizzes', methods=['GET', 'POST'])
@login_required
def admin_quizzes():
    u = find_user(session['user'])
    if u['role'] != 'admin':
        abort(403)
    if request.method == 'POST':
        new_id = str(uuid.uuid4())
        write_quiz({
            'id': new_id,
            'course_id': request.form['course_id'],
            'question': request.form['question'],
            'options': request.form['options'],
            'answer': request.form['answer']
        })
        flash('Quiz added successfully!', 'success')
    return render_template('admin_quizzes.html', courses=read_courses(), quizzes=read_quizzes())

@app.route('/admin/export')
@login_required
def admin_export():
    u = find_user(session['user'])
    if u['role'] != 'admin':
        abort(403)
    files = ['users', 'courses', 'enrollments', 'quizzes', 'quiz_results']
    return render_template('admin_export.html', files=files)

@app.route('/admin/export/<name>')
@login_required
def download(name):
    u = find_user(session['user'])
    if u['role'] != 'admin':
        abort(403)
    path = csv_path(f"{name}.csv")
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=f"{name}.csv")

if __name__ == '__main__':
    app.run(debug=True)
