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
# Ensure storage directories
os.makedirs(os.path.join(top, 'instance'), exist_ok=True)

# --- CSV Helpers ---
def csv_path(filename):
    return os.path.join(top, 'instance', filename)

def read_csv(name, fields):
    path = csv_path(name)
    if not os.path.exists(path):
        return []
    with open(path, newline='') as f:
        reader = csv.DictReader(f)
        return list(reader)

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

# User
read_users = lambda: read_csv('users.csv', USER_FIELDS)
write_user = lambda u, ph, r: append_csv('users.csv', {'username': u, 'password_hash': ph, 'role': r}, USER_FIELDS)
find_user = lambda u: next((x for x in read_users() if x['username']==u), None)

# Courses
read_courses = lambda: read_csv('courses.csv', COURSE_FIELDS)
write_course = lambda c: append_csv('courses.csv', c, COURSE_FIELDS)
find_course = lambda cid: next((c for c in read_courses() if c['id']==cid), None)

# Enrollment
enroll_user = lambda u, cid: append_csv('enrollments.csv', {'username': u, 'course_id': cid}, ENROLL_FIELDS)
read_enroll = lambda: read_csv('enrollments.csv', ENROLL_FIELDS)
is_enrolled = lambda u, cid: any(e for e in read_enroll() if e['username']==u and e['course_id']==cid)

# Quizzes
read_quizzes = lambda: read_csv('quizzes.csv', QUIZ_FIELDS)
write_quiz = lambda q: append_csv('quizzes.csv', q, QUIZ_FIELDS)
course_quizzes = lambda cid: [q for q in read_quizzes() if q['course_id']==cid]

# Results
write_result = lambda r: append_csv('quiz_results.csv', r, RESULT_FIELDS)
user_results = lambda u: [r for r in read_csv('quiz_results.csv', RESULT_FIELDS) if r['username']==u]

# --- OAuth & Mail Setup ---
google_bp = make_google_blueprint(
    client_id=os.environ.get('GOOGLE_OAUTH_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET'),
    scope=["profile","email"],
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

# --- Context Processors ---
@app.context_processor
def inject_utils():
    return dict(find_user=find_user, read_users=read_users, read_courses=read_courses,
                read_enroll=read_enroll, read_quizzes=read_quizzes)

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
    for i,title in enumerate([('Intro to AI','Basics of AI'),('Machine Learning','ML algorithms')],1):
        write_course({'id':str(i),'title':title[0],'description':title[1],'educator':'admin','status':'active'})

# --- Routes ---
@app.route('/')
@login_required
def catalog():
    courses = [c for c in read_courses() if c['status']=='active']
    return render_template('catalog.html', courses=courses)

@app.route('/course/<cid>')
@login_required
def course_detail(cid):
    c = find_course(cid)
    if not c: abort(404)
    return render_template('course_detail.html', course=c,
                           enrolled=is_enrolled(session['user'],cid))

@app.route('/enroll/<cid>')
@login_required
def enroll(cid):
    if not is_enrolled(session['user'],cid): enroll_user(session['user'],cid)
    return redirect(url_for('course_detail',cid=cid))

@app.route('/profile')
@login_required
def profile():
    u = find_user(session['user'])
    if u['role']=='student':
        all_courses = [c for c in read_courses() if c['status']=='active']
        enrolled = [c for c in all_courses if is_enrolled(u['username'],c['id'])]
        available = [c for c in all_courses if not is_enrolled(u['username'],c['id'])]
        return render_template('student_profile.html', user=u,
                               enrolled=enrolled, available=available)
    if u['role']=='educator':
        own = [c for c in read_courses() if c['educator']==u['username']]
        return render_template('educator_profile.html', user=u, courses=own)
    return render_template('admin_dashboard.html')

@app.route('/educator/add_course', methods=['POST'])
@login_required
def educator_add_course():
    u = find_user(session['user'])
    if u['role']!='educator': abort(403)
    cid=str(uuid.uuid4())
    write_course({'id':cid,'title':request.form['title'],
                  'description':request.form['description'],
                  'educator':u['username'],'status':'active'})
    return redirect(url_for('profile'))

@app.route('/login/google/authorized')
def google_authorized():
    if not google.authorized: return redirect(url_for('login'))
    resp=google.get('/oauth2/v1/userinfo')
    info=resp.json() if resp.ok else None
    if not info: return redirect(url_for('login'))
    email=info.get('email')
    user=find_user(email) or write_user(email,generate_password_hash(uuid.uuid4().hex),'student')
    session['user']=email
    return redirect(url_for('catalog'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method=='POST':
        write_user(request.form['username'],
                   generate_password_hash(request.form['password']),
                   request.form['role'])
        return redirect(url_for('login'))
    return render_template('register.html', roles=['student','educator'])

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        u=find_user(request.form['username'])
        if u and check_password_hash(u['password_hash'],request.form['password']):
            session['user']=u['username']
            return redirect(url_for('catalog'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin/courses', methods=['GET','POST'])
@login_required
def admin_courses():
    if find_user(session['user'])['role']!='admin': abort(403)
    if request.method=='POST':
        cid=str(uuid.uuid4())
        write_course({'id':cid,'title':request.form['title'],
                      'description':request.form['description'],
                      'educator':request.form['educator'],'status':'pending'})
    return render_template('admin_courses.html', courses=read_courses(), users=read_users())

@app.route('/admin/quizzes', methods=['GET','POST'])
@login_required
def admin_quizzes():
    if find_user(session['user'])['role']!='admin': abort(403)
    if request.method=='POST':
        qid=str(uuid.uuid4())
        write_quiz({'id':qid,'course_id':request.form['course_id'],
                    'question':request.form['question'],
                    'options':request.form['options'],
                    'answer':request.form['answer']})
    return render_template('admin_quizzes.html', courses=read_courses(), quizzes=read_quizzes())

@app.route('/admin/export')
@login_required
def admin_export():
    if find_user(session['user'])['role']!='admin': abort(403)
    return render_template('admin_export.html', files=['users','courses','enrollments','quizzes','quiz_results'])

@app.route('/admin/export/<name>')
@login_required
def download(name):
    if find_user(session['user'])['role']!='admin': abort(403)
    path=csv_path(f"{name}.csv")
    if not os.path.exists(path): abort(404)
    return send_file(path, as_attachment=True, download_name=f"{name}.csv")

if __name__=='__main__':
    app.run(debug=True)
