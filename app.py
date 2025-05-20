import os, csv, uuid
from flask import (
    Flask, render_template, redirect, url_for,
    request, flash, session, send_file, abort
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

# Initialization
top = os.path.dirname(__file__)
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev')

# Ensure dirs
os.makedirs(os.path.join(top,'instance'), exist_ok=True)
os.makedirs(os.path.join(top,'static','videos'), exist_ok=True)

# CSV path helper
def csv_path(fname): return os.path.join(top,'instance',fname)

# Generic CSV read/write
def read_csv(name, fields):
    path = csv_path(name)
    rows = []
    if os.path.exists(path):
        with open(path, newline='') as f:
            reader = csv.DictReader(f, fieldnames=fields)
            next(reader, None)
            for row in reader:
                rows.append(row)
    return rows

def append_csv(name, row, fields):
    path = csv_path(name)
    exists = os.path.exists(path)
    with open(path, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        if not exists:
            writer.writeheader()
        writer.writerow(row)

# Models
USER_FIELDS = ['username','password_hash','role']
COURSE_FIELDS = ['id','title','description','educator','status']
ENROLL_FIELDS = ['username','course_id']
VIDEO_FIELDS = ['course_id','filename']
QUIZ_FIELDS = ['id','course_id','question','options','answer']
RESULT_FIELDS = ['username','quiz_id','selected','correct']

read_users = lambda: read_csv('users.csv', USER_FIELDS)
write_user = lambda u,ph,role: append_csv('users.csv',{'username':u,'password_hash':ph,'role':role},USER_FIELDS)
find_user = lambda u: next((x for x in read_users() if x['username']==u), None)

read_courses = lambda: read_csv('courses.csv', COURSE_FIELDS)
write_course = lambda c: append_csv('courses.csv', c, COURSE_FIELDS)
find_course = lambda cid: next((c for c in read_courses() if c['id']==cid), None)

read_enroll = lambda: read_csv('enrollments.csv', ENROLL_FIELDS)
enroll_user = lambda u,cid: append_csv('enrollments.csv',{'username':u,'course_id':cid},ENROLL_FIELDS)
is_enrolled = lambda u,cid:any(e for e in read_enroll() if e['username']==u and e['course_id']==cid)

read_videos = lambda: read_csv('videos.csv', VIDEO_FIELDS)
map_video = lambda cid: next((v['filename'] for v in read_videos() if v['course_id']==cid), None)
save_video = lambda cid,fn: append_csv('videos.csv',{'course_id':cid,'filename':fn},VIDEO_FIELDS)

read_quizzes = lambda: read_csv('quizzes.csv', QUIZ_FIELDS)
write_quiz = lambda q: append_csv('quizzes.csv', q, QUIZ_FIELDS)
course_quizzes = lambda cid: [q for q in read_quizzes() if q['course_id']==cid]

write_result = lambda r: append_csv('quiz_results.csv', r, RESULT_FIELDS)
user_results = lambda u: [r for r in read_csv('quiz_results.csv', RESULT_FIELDS) if r['username']==u]

# OAuth & Mail
google_bp = make_google_blueprint(
    client_id=os.environ.get('GOOGLE_OAUTH_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET'),
    scope=["profile","email"],
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

# Defaults
if not find_user('admin'):
    write_user('admin', generate_password_hash('comp2801'), 'admin')
if not os.path.exists(csv_path('courses.csv')):
    sample_courses = [
        {'id':'1','title':'Intro to AI','description':'Basics of AI','educator':'admin','status':'active'},
        {'id':'2','title':'Machine Learning','description':'ML algorithms','educator':'admin','status':'active'}
    ]
    for c in sample_courses:
        write_course(c)

# Routes
@app.route('/')
def catalog():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('catalog.html', courses=read_courses())

@app.route('/course/<cid>')
def course_detail(cid):
    course = find_course(cid)
    if not course:
        abort(404)
    return render_template('course_detail.html', course=course, enrolled=is_enrolled(session.get('user'), cid), video=map_video(cid))

@app.route('/enroll/<cid>')
def enroll(cid):
    if 'user' not in session:
        return redirect(url_for('login'))
    enroll_user(session['user'], cid)
    flash('Enrolled!', 'success')
    return redirect(url_for('course_detail', cid=cid))

@app.route('/lesson/<cid>')
def lesson(cid):
    if not is_enrolled(session.get('user'), cid):
        abort(403)
    course = find_course(cid)
    return render_template('lesson.html', course=course, video=map_video(cid))

@app.route('/quiz/<cid>', methods=['GET','POST'])
def take_quiz(cid):
    quizzes = course_quizzes(cid)
    if request.method == 'POST':
        score = 0
        for q in quizzes:
            sel = request.form.get(q['id'])
            write_result({
                'username': session['user'],
                'quiz_id': q['id'],
                'selected': sel,
                'correct': str(q['answer'])
            })
            if sel == str(q['answer']):
                score += 1
        return render_template('quiz_result.html', score=score, total=len(quizzes))
    return render_template('take_quiz.html', quizzes=quizzes)

@app.route('/profile')
def profile():
    user = find_user(session['user'])
    if user['role'] == 'student':
        enrolls = read_enroll()
        results = user_results(session['user'])
        return render_template('student_profile.html', user=user, enrolls=enrolls, results=results)
    elif user['role'] == 'educator':
        courses = [c for c in read_courses() if c['educator'] == session['user']]
        return render_template('educator_profile.html', user=user, courses=courses)
    else:
        return render_template('admin_dashboard.html')

@app.route('/register', methods=['GET','POST'])
def register():
    roles = ['student', 'educator']
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        write_user(username, generate_password_hash(password), role)
        flash('Account created!','success')
        return redirect(url_for('login'))
    return render_template('register.html', roles=roles)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        user = find_user(u)
        if user and check_password_hash(user['password_hash'], p):
            session['user'] = u
            flash('Welcome back!','success')
            return redirect(url_for('profile'))
        flash('Invalid credentials','danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.','info')
    return redirect(url_for('login'))

@app.route('/admin/courses', methods=['GET','POST'])
def admin_courses():
    if find_user(session.get('user'))['role'] != 'admin':
        abort(403)
    if request.method == 'POST':
        cid = str(uuid.uuid4())
        write_course({
            'id': cid,
            'title': request.form['title'],
            'description': request.form['description'],
            'educator': request.form['educator'],
            'status': 'pending'
        })
        flash('Course added.','success')
    return render_template('admin_courses.html', courses=read_courses(), users=read_users())

@app.route('/admin/quizzes', methods=['GET','POST'])
def admin_quizzes():
    if find_user(session.get('user'))['role'] != 'admin':
        abort(403)
    if request.method == 'POST':
        qid = str(uuid.uuid4())
        write_quiz({
            'id': qid,
            'course_id': request.form['course_id'],
            'question': request.form['question'],
            'options': request.form['options'],
            'answer': request.form['answer']
        })
        flash('Quiz added.','success')
    return render_template('admin_quizzes.html', courses=read_courses(), quizzes=read_quizzes())

@app.route('/admin/export')
def admin_export():
    if find_user(session.get('user'))['role'] != 'admin':
        abort(403)
    files = ['users','courses','enrollments','videos','quizzes','quiz_results']
    return render_template('admin_export.html', files=files)

@app.route('/admin/export/<name>')
def download(name):
    if find_user(session.get('user'))['role'] != 'admin':
        abort(403)
    path = csv_path(f"{name}.csv")
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=f"{name}.csv")

if __name__=='__main__':
    app.run(debug=True)
