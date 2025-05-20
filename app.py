import os
import csv
import uuid
from functools import wraps
from flask import (
    Flask, render_template, redirect, url_for,
    request, flash, session, send_file, abort
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer

# --- App Initialization ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev')

top = os.path.dirname(__file__)
# Ensure storage directories
os.makedirs(os.path.join(top, 'instance'), exist_ok=True)
os.makedirs(os.path.join(top, 'static', 'videos'), exist_ok=True)

# --- CSV Helpers ---
def csv_path(filename):
    return os.path.join(top, 'instance', filename)

def read_csv(name, fields):
    path = csv_path(name)
    rows = []
    if os.path.exists(path):
        with open(path, newline='') as f:
            reader = csv.DictReader(f, fieldnames=fields)
            next(reader, None)
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
VIDEO_FIELDS = ['course_id', 'filename']
QUIZ_FIELDS = ['id', 'course_id', 'question', 'options', 'answer']
RESULT_FIELDS = ['username', 'quiz_id', 'selected', 'correct']

read_users = lambda: read_csv('users.csv', USER_FIELDS)
write_user = lambda u, ph, r: append_csv('users.csv', {'username': u, 'password_hash': ph, 'role': r}, USER_FIELDS)
find_user = lambda u: next((x for x in read_users() if x['username'] == u), None)

read_courses = lambda: read_csv('courses.csv', COURSE_FIELDS)
write_course = lambda c: append_csv('courses.csv', c, COURSE_FIELDS)
find_course = lambda cid: next((c for c in read_courses() if c['id'] == cid), None)

read_enroll = lambda: read_csv('enrollments.csv', ENROLL_FIELDS)
enroll_user = lambda u, cid: append_csv('enrollments.csv', {'username': u, 'course_id': cid}, ENROLL_FIELDS)
is_enrolled = lambda u, cid: any(e for e in read_enroll() if e['username'] == u and e['course_id'] == cid)

read_videos = lambda: read_csv('videos.csv', VIDEO_FIELDS)
map_video = lambda cid: next((v['filename'] for v in read_videos() if v['course_id'] == cid), None)
save_video = lambda cid, fn: append_csv('videos.csv', {'course_id': cid, 'filename': fn}, VIDEO_FIELDS)

read_quizzes = lambda: read_csv('quizzes.csv', QUIZ_FIELDS)
write_quiz = lambda q: append_csv('quizzes.csv', q, QUIZ_FIELDS)
course_quizzes = lambda cid: [q for q in read_quizzes() if q['course_id'] == cid]

write_result = lambda r: append_csv('quiz_results.csv', r, RESULT_FIELDS)
user_results = lambda u: [r for r in read_csv('quiz_results.csv', RESULT_FIELDS) if r['username'] == u]

# --- OAuth & Email ---
google_bp = make_google_blueprint(
    client_id=os.environ.get('GOOGLE_OAUTH_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET'),
    scope=["profile", "email"],
    redirect_url='/login/google/authorized'
)
app.register_blueprint(google_bp, url_prefix='/login')

app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD')
)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- Context Processor ---
@app.context_processor
def inject_utils():
    return {
        'find_user': find_user,
        'read_users': read_users,
        'read_courses': read_courses,
        'read_enroll': read_enroll,
        'read_quizzes': read_quizzes
    }

# --- Authentication Decorator ---
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# --- Default Admin & Sample Data ---
if not find_user('admin'):
    write_user('admin', generate_password_hash('comp2801'), 'admin')
if not os.path.exists(csv_path('courses.csv')):
    for i, (t, d) in enumerate([('Intro to AI', 'Basics of AI'), ('Machine Learning', 'ML algorithms')], 1):
        write_course({'id': str(i), 'title': t, 'description': d, 'educator': 'admin', 'status': 'active'})

# --- Routes ---
@app.route('/')
@login_required
def catalog():
    return render_template('catalog.html', courses=read_courses())

@app.route('/course/<cid>')
@login_required
def course_detail(cid):
    course = find_course(cid)
    if not course:
        abort(404)
    return render_template('course_detail.html', course=course, enrolled=is_enrolled(session['user'], cid), video=map_video(cid))

@app.route('/enroll/<cid>')
@login_required
def enroll(cid):
    enroll_user(session['user'], cid)
    flash('Enrolled!', 'success')
    return redirect(url_for('course_detail', cid=cid))

@app.route('/lesson/<cid>')
@login_required
def lesson(cid):
    if not is_enrolled(session['user'], cid):
        abort(403)
    return render_template('lesson.html', course=find_course(cid), video=map_video(cid))

@app.route('/quiz/<cid>', methods=['GET', 'POST'])
@login_required
def take_quiz(cid):
    quizzes = course_quizzes(cid)
    if request.method == 'POST':
        score = 0
        for q in quizzes:
            sel = request.form.get(q['id'])
            write_result({'username': session['user'], 'quiz_id': q['id'], 'selected': sel, 'correct': str(q['answer'])})
            if sel == str(q['answer']): score += 1
        return render_template('quiz_result.html', score=score, total=len(quizzes))
    return render_template('take_quiz.html', quizzes=quizzes)

@app.route('/profile')
@login_required
def profile():
    user = find_user(session['user'])
    if user['role'] == 'student':
        return render_template('student_profile.html', user=user, enrolls=read_enroll(), results=user_results(session['user']))
    elif user['role'] == 'educator':
        return render_template('educator_profile.html', user=user, courses=[c for c in read_courses() if c['educator']==session['user']])
    return render_template('admin_dashboard.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    roles = ['student', 'educator']
    if request.method == 'POST':
        write_user(request.form['username'], generate_password_hash(request.form['password']), request.form['role'])
        flash('Account created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', roles=roles)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = find_user(request.form['username'])
        if user and check_password_hash(user['password_hash'], request.form['password']):
            session['user'] = user['username']
            flash('Welcome back!', 'success')
            return redirect(url_for('profile'))
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
    if find_user(session['user'])['role'] != 'admin': abort(403)
    if request.method == 'POST':
        cid = str(uuid.uuid4())
        write_course({'id': cid, 'title': request.form['title'], 'description': request.form['description'], 'educator': request.form['educator'], 'status': 'pending'})
        flash('Course added.', 'success')
    return render_template('admin_courses.html', courses=read_courses(), users=read_users())

@app.route('/admin/quizzes', methods=['GET', 'POST'])
@login_required
def admin_quizzes():
    if find_user(session['user'])['role'] != 'admin': abort(403)
    if request.method == 'POST':
        qid = str(uuid.uuid4())
        write_quiz({'id': qid, 'course_id': request.form['course_id'], 'question': request.form['question'], 'options': request.form['options'], 'answer': request.form['answer']})
        flash('Quiz added.', 'success')
    return render_template('admin_quizzes.html', courses=read_courses(), quizzes=read_quizzes())

@app.route('/admin/export')
@login_required
def admin_export():
    if find_user(session['user'])['role'] != 'admin': abort(403)
    files = ['users','courses','enrollments','videos','quizzes','quiz_results']
    return render_template('admin_export.html', files=files)

@app.route('/admin/export/<name>')
@login_required
def download(name):
    if find_user(session['user'])['role'] != 'admin': abort(403)
    path = csv_path(f"{name}.csv")
    if not os.path.exists(path): abort(404)
    return send_file(path, as_attachment=True, download_name=f"{name}.csv")

@app.route('/educator/add_course', methods=['POST'])
@login_required
def educator_add_course():
    user = find_user(session['user'])
    if user['role'] != 'educator':
        abort(403)
    # generate a new course record, mark as active so students can enroll immediately
    cid = str(uuid.uuid4())
    write_course({
        'id': cid,
        'title':   request.form['title'],
        'description': request.form['description'],
        'educator':    user['username'],
        'status':      'active'
    })
    flash('Course created! Students can now enroll.', 'success')
    return redirect(url_for('profile'))

if __name__ == '__main__':
    app.run(debug=True)
