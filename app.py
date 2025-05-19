import os, csv, uuid, json
from flask import (
    Flask, render_template, redirect, url_for,
    request, flash, session, send_file, abort, jsonify
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
    path=csv_path(name)
    data=[]
    if os.path.exists(path):
        with open(path,newline='') as f:
            r=csv.DictReader(f,fieldnames=fields)
            next(r,None)
            for row in r: data.append(row)
    return data

def append_csv(name,row,fields):
    path=csv_path(name)
    exists=os.path.exists(path)
    with open(path,'a',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields)
        if not exists: w.writeheader()
        w.writerow(row)

# Models
USER_FIELDS=['username','password_hash','role']
COURSE_FIELDS=['id','title','description','educator','status']
ENROLL_FIELDS=['username','course_id']
VIDEO_FIELDS=['course_id','filename']
QUIZ_FIELDS=['id','course_id','question','options','answer']
RESULT_FIELDS=['username','quiz_id','selected','correct']
LECT_FIELDS=['id','course_id','title','start']

read_users=lambda: read_csv('users.csv',USER_FIELDS)
write_user=lambda u,ph,role: append_csv('users.csv',{'username':u,'password_hash':ph,'role':role},USER_FIELDS)
find_user=lambda u: next((x for x in read_users() if x['username']==u),None)

read_courses=lambda: read_csv('courses.csv',COURSE_FIELDS)
write_course=lambda c: append_csv('courses.csv',c,COURSE_FIELDS)
find_course=lambda cid: next((c for c in read_courses() if c['id']==cid),None)

read_enroll=lambda: read_csv('enrollments.csv',ENROLL_FIELDS)
enroll_user=lambda u,cid: append_csv('enrollments.csv',{'username':u,'course_id':cid},ENROLL_FIELDS)
is_enrolled=lambda u,cid:any(e for e in read_enroll() if e['username']==u and e['course_id']==cid)

read_videos=lambda: read_csv('videos.csv',VIDEO_FIELDS)
map_video=lambda cid: next((v['filename'] for v in read_videos() if v['course_id']==cid),None)
save_video=lambda cid,fn: append_csv('videos.csv',{'course_id':cid,'filename':fn},VIDEO_FIELDS)

read_quizzes=lambda: read_csv('quizzes.csv',QUIZ_FIELDS)
write_quiz=lambda q: append_csv('quizzes.csv',q,QUIZ_FIELDS)
course_quizzes=lambda cid:[q for q in read_quizzes() if q['course_id']==cid]

write_result=lambda r: append_csv('quiz_results.csv',r,RESULT_FIELDS)
user_results=lambda u:[r for r in read_csv('quiz_results.csv',RESULT_FIELDS) if r['username']==u]

read_lectures=lambda: read_csv('lectures.csv',LECT_FIELDS)
write_lecture=lambda l: append_csv('lectures.csv',l,LECT_FIELDS)

# OAuth & Mail
google_bp = make_google_blueprint(
    client_id=os.environ.get('GOOGLE_OAUTH_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET'),
    scope=["profile","email"],
    redirect_url='/login/google/authorized'
)
app.register_blueprint(google_bp,url_prefix='/login')

app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD')
)
mail=Mail(app)
serializer=URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Defaults
if not find_user('admin'): write_user('admin',generate_password_hash('comp2801'),'admin')
if not os.path.exists(csv_path('courses.csv')):
    for i,(t,d) in enumerate([('Intro AI','Basics'),('ML','Algorithms')], start=1):
        write_course({'id':str(i),'title':t,'description':d,'educator':'admin','status':'active'})

# Routes
@app.route('/')
def catalog():
    if 'user' not in session: return redirect(url_for('login'))
    return render_template('catalog.html',courses=read_courses())

@app.route('/course/<cid>')
def course_detail(cid):
    c=find_course(cid); abort(404) if not c else None
    return render_template('course_detail.html',course=c,enrolled=is_enrolled(session['user'],cid),video=map_video(cid))

@app.route('/enroll/<cid>')
def enroll(cid):
    enroll_user(session['user'],cid); flash('Enrolled!','success')
    return redirect(url_for('course_detail',cid=cid))

@app.route('/lesson/<cid>')
def lesson(cid):
    abort(403) if not is_enrolled(session.get('user'),cid) else None
    return render_template('lesson.html',course=find_course(cid),video=map_video(cid))

@app.route('/quiz/<cid>',methods=['GET','POST'])
def take_quiz(cid):
    qs=course_quizzes(cid)
    if request.method=='POST':
        s=0
        for q in qs:
            sel=request.form.get(q['id']); write_result({'username':session['user'],'quiz_id':q['id'],'selected':sel,'correct':str(q['answer'])})
            s+=1 if sel==str(q['answer']) else 0
        return render_template('quiz_result.html',score=s,total=len(qs))
    return render_template('take_quiz.html',quizzes=qs)

@app.route('/profile')
def profile():
    u=find_user(session['user'])
    if u['role']=='student': return render_template('student_profile.html',user=u,enrolls=read_enroll(),results=user_results(session['user']))
    if u['role']=='educator': return render_template('educator_profile.html',user=u,courses=[c for c in read_courses() if c['educator']==u['username']],lectures=read_lectures())
    return render_template('admin_dashboard.html')

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST': write_user(request.form['username'],generate_password_hash(request.form['password']),request.form['role']);flash('OK','success');return redirect(url_for('login'))
    return render_template('register.html',roles=['student','educator'])

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        u=request.form['username'];pw=request.form['password']
        if (usr:=find_user(u)) and check_password_hash(usr['password_hash'],pw):session['user']=u;flash('Welcome','success');return redirect(url_for('profile'))
        flash('Invalid','danger')
    return render_template('login.html')

@app.route('/logout')
def logout(): session.clear(); flash('Bye','info'); return redirect(url_for('login'))

@app.route('/admin/courses',methods=['GET','POST'])
def admin_courses():
    if find_user(session['user'])['role']!='admin':abort(403)
    if request.method=='POST': write_course({'id':str(uuid.uuid4()),'title':request.form['title'],'description':request.form['description'],'educator':request.form['educator'],'status':'pending'});flash('Added','success')
    return render_template('admin_courses.html',courses=read_courses(),users=read_users())

@app.route('/admin/quizzes',methods=['GET','POST'])
def admin_quizzes():
    if find_user(session['user'])['role']!='admin':abort(403)
    if request.method=='POST': write_quiz({'id':str(uuid.uuid4()),'course_id':request.form['course_id'],'question':request.form['question'],'options':request.form['options'],'answer':request.form['answer']});flash('Added','success')
    return render_template('admin_quizzes.html',courses=read_courses(),quizzes=read_quizzes())

@app.route('/admin/export')
def admin_export():
    if find_user(session['user'])['role']!='admin':abort(403)
    return render_template('admin_export.html',files=['users','courses','enrollments','videos','quizzes','quiz_results','lectures'])

@app.route('/admin/export/<name>')
def download(name):
    if find_user(session['user'])['role']!='admin':abort(403)
    path=csv_path(f"{name}.csv");abort(404) if not os.path.exists(path) else None
    return send_file(path,as_attachment=True,download_name=f"{name}.csv")

@app.route('/calendar_events')
def calendar_events(): return jsonify([{'id':l['id'],'title':l['title'],'start':l['start']} for l in read_lectures()])

@app.route('/calendar')
def calendar(): return render_template('calendar.html')

if __name__=='__main__': app.run(debug=True)
