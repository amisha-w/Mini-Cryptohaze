from flask import Flask, redirect, url_for, render_template, request, session, flash, Markup, send_file, Response
from hash import cracksingle, crackfile, hash_type, encrypt_all,returnResult, clearResult, threaded
from werkzeug.utils import secure_filename
from wtforms import Form, StringField, TextAreaField, PasswordField, FileField, SelectField, TextField, validators
from wtforms.validators import DataRequired, Email
from passlib.hash import sha256_crypt
from wtforms.fields.html5 import EmailField, DateField
import json, os, re, time, requests, datetime
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from passwordStrength import findStrength
import concurrent.futures
import multiprocessing
import hashlib, random 

app = Flask(__name__)
app.secret_key = '123456'
app.config["UPLOAD_FOLDER"] = "data"

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

# Creating an instance of SQLAlchemy class ...
db = SQLAlchemy(app)

class User(db.Model):
	username = db.Column(db.String(40), primary_key = True, nullable=False)
	name = db.Column(db.String(), nullable=False)
	password = db.Column(db.String(), nullable=False)

# Form Validation for RegisterForm
class RegisterForm(Form):
	username = TextField('Username', [DataRequired(), validators.length(min=4, max=13)])
	name = TextField('Full Name', [DataRequired(), validators.length(max=80)])
	password = PasswordField('Password', [
		DataRequired(), 
		validators.length(min=4, max=25),
		validators.EqualTo('confirm', message='Passwords do not match !')
		])
	confirm = PasswordField('Confirm Password')

# Form Validation for LoginForm
class LoginForm(Form):
	username = TextField('Username', [DataRequired(), validators.length(min=4, max=13)])
	password = PasswordField('Password', [DataRequired(), validators.length(min=4, max=25)])

@app.route('/')
def index():
    if 'logged_in' in session:
        return render_template("index.html", logged_in=True, username=session['username'])
    return render_template("index.html", logged_in=False)

     

@app.route('/register' , methods=['POST', 'GET'])
def register():
    form = RegisterForm(request.form)
    try:
        if request.method == 'POST' and form.validate():
            username = request.form["username"]
            name = request.form["name"]
            password = sha256_crypt.hash(str(request.form["password"]))
            user = User(username=username, name=name, password=password)
            db.session.add(user)
            db.session.commit()
            session['username']	= username
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template("register.html", form=form)
    except Exception as e:
        return render_template('register.html', form=form)

def is_logged_in(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session:
			return f(*args, **kwargs)
		else:
			flash('Unauthorized, Please Login !', category='danger')
			return render_template('index.html', logged_in=False)
	return wrap


@app.route('/logout' , methods=['POST', 'GET'])
@is_logged_in
def logout():
	session.clear()
	return redirect(url_for('index'))

@app.route('/login' , methods=['POST', 'GET'])
def login():
    form = LoginForm(request.form)
    try:
        if request.method == 'POST' and form.validate():
            username = request.form["username"]
            password = request.form["password"]
            try:
                user = User.query.filter_by(username=username).first()
                # Compare Passwords...
                if sha256_crypt.verify(password, user.password):
                    session['username'] = username
                    session['logged_in'] = True
                    return redirect(url_for('index'))
                else:
                    return render_template("login.html", form=form, logged_in=False)
            except Exception as e:
                return render_template("login.html", form=form, logged_in=False)        
        else:
            return render_template("login.html", form=form, logged_in=False)
    except Exception as e:
        return render_template("index.html", logged_in=False)


@app.route('/identifyhash', methods = ['POST','GET'])
def identifyhash():
    hash = "empty"
    if request.method == 'POST':
        hashvalue = request.form['hashvalue']
        hash = hash_type(hashvalue)
        if 'logged_in' in session:
                username = session["username"]
                filepath = os.path.join(app.config['UPLOAD_FOLDER'],"logs", username + '.txt')
                with open(filepath, "a") as userfile:
                    userfile.write(datetime.datetime.today().strftime("%d/%m/%Y %H:%M:%S")+" IH - "+ hashvalue+" "+hash+" -\n")
    if 'logged_in' in session:
        return render_template("identifyhash.html", value = hash, logged_in=True, username = session['username'])
    return render_template("identifyhash.html", value = hash, logged_in=False)


@app.route('/crackhash', methods = ['POST','GET'])
def crackhash():
    value, hash = "", ""
    timetocrack = 0
    word_dict = None
    if request.method == 'POST':
        hashvalue = request.form['hashvalue']
        option = request.form['options']
        if option == "custom":
            wordlist = request.files['wordlist']
            wordpath = os.path.join(app.config['UPLOAD_FOLDER'], "wordlists", wordlist.filename)
            wordlist.save(wordpath)
            word_dict = encrypt_all(wordpath)
        start_time = time.time()
        value = cracksingle(hashvalue, word_dict)
        hash = hash_type(hashvalue)
        timetocrack = (time.time() - start_time)
        if 'logged_in' in session:
            username = session["username"]
            filepath = os.path.join(app.config['UPLOAD_FOLDER'],"logs", username + '.txt')
            with open(filepath, "a") as userfile:
                userfile.write(datetime.datetime.today().strftime("%d/%m/%Y %H:%M:%S")+" CH - "+hashvalue+" "+hash+" "+value)
    if 'logged_in' in session:
        return render_template("crackhash.html", value=value, time = timetocrack, logged_in=True, username = session['username'], hashtype=hash)
    return render_template("crackhash.html", value=value, time = timetocrack,  logged_in=False, hashtype=hash)


@app.route('/crackhashfromfile', methods = ['POST','GET'])
def crackhashfromfile():
    timetocrack = 0
    value, string, finalV = "", "", []
    word_dict = None
    if request.method == 'POST':
        f = request.files['hashfile']
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
        f.save(filepath)

        option = request.form['options']
        if option == "custom":
            wordlist = request.files['wordlist']
            wordpath = os.path.join(app.config['UPLOAD_FOLDER'], "wordlists", wordlist.filename)
            wordlist.save(wordpath)
            word_dict = encrypt_all(wordpath)

        start_time = time.time()
        value = crackfile(filepath, word_dict)
        for row in value:
            finalV.append([row[0],hash_type(row[0]),row[1]])
                
        timetocrack = (time.time() - start_time)    
        for row in value:
            for column in row:
                string+=column+" "
            string+="\n"
        if 'logged_in' in session:
            username = session["username"]
            filepath = os.path.join(app.config['UPLOAD_FOLDER'],"logs", username + '.txt')
            with open(filepath, "a") as userfile:
                st = ""
                for row in value:
                    st+= datetime.datetime.today().strftime("%d/%m/%Y %H:%M:%S")+" CF "+f.filename+" "
                    st += row[0]+" "+ hash_type(row[0])+" "+row[1]
                    st+="\n"
                userfile.write(st)
    if 'logged_in' in session:
        return render_template("crackhashfromfile.html", rows=finalV, download=string, time = timetocrack, logged_in=True, username = session['username'])
    return render_template("crackhashfromfile.html", rows=finalV, download=string, time = timetocrack,  logged_in=False)

@app.route('/crackhashfromdir', methods = ['POST','GET'])
def crackhashfromdir():
    timetocrack = 0
    value = []
    string  = ""
    fnames = []
    word_dict = None
    if request.method == 'POST':
        st=""
        files = request.files.getlist("hashdir")
        option = request.form['options']
        if option == "custom":
            wordlist = request.files['wordlist']
            wordpath = os.path.join(app.config['UPLOAD_FOLDER'], "wordlists", wordlist.filename)
            wordlist.save(wordpath)
            word_dict = encrypt_all(wordpath)
        start_time = time.time()
        for file in files:
            fname = file.filename.replace("/","-")
            if fname[-4:]==".txt":
                finalV = []
                file.save(os.path.join(app.config['UPLOAD_FOLDER'],fname))
                fnames.append(file.filename)
                string+=file.filename+"\n"
                table = crackfile(os.path.join(app.config['UPLOAD_FOLDER'], fname),word_dict)
                for row in table:
                    finalV.append([row[0],hash_type(row[0]),row[1]])
                timetocrack = (time.time() - start_time)
                value.append(finalV)
                
                for row in table:
                    st+= datetime.datetime.today().strftime("%d/%m/%Y %H:%M:%S")+" CD "+file.filename+" "
                    for column in row:
                        string+=column+" "
                    st += row[0]+" "+ hash_type(row[0])+" "+row[1] +"\n"
                    string+="\n"
                
        if 'logged_in' in session:
            username = session["username"]
            filepath = os.path.join(app.config['UPLOAD_FOLDER'],"logs", username + '.txt')
            with open(filepath, "a") as userfile:
                userfile.write(st)
    if 'logged_in' in session:
        return render_template("crackhashfromdir.html",tables=value,download=string,fnames = fnames,time = timetocrack, logged_in=True, username = session['username'])
    return render_template("crackhashfromdir.html",tables=value,download=string,fnames = fnames,time = timetocrack,  logged_in=False)


    
@app.route('/statistics')
def statistics(): 
    if 'logged_in' in session:
        return render_template("statistics.html", logged_in=True, username = session['username']) 
    return render_template("statistics.html", logged_in=False)


threads = 0
filethread = ""

def minerthread(word_dict=None):
    global xx
    xx = "-"
    clearResult()
    lines = []
    found = set()
    with open(filethread, 'r') as f:
        for line in f:
            y = line.strip('\n')
            x = y.split('\t')
            for i in x:             
                lines.append(i)
    for line in lines:
        matches = re.findall(r'[a-f0-9]{128}|[a-f0-9]{96}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32}', line)
        if matches:
            for match in matches:
                found.add(match)
    print ('Hashes found: %i' % (len(found)))
    m = multiprocessing.Manager()
    lock = m.Lock()
    threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=int(threads))
    futures = (threadpool.submit(threaded, hashvalue, lock, word_dict) for hashvalue in found)
    for i, _ in enumerate(concurrent.futures.as_completed(futures)):
        # a = 1
        if i + 1 == len(found) or (i + 1) % 10 == 0: 
            # time elapsed ==1s or 0.5s
            print('Progress: %i/%i' % (i + 1, len(found)), end='\r')
            xx = str(i + 1)+" "+str(len(found))


@app.route('/concurrentthread', methods = ['POST','GET'])
def concurrentthread():
    global filethread
    global threads
    global done
    timetocrack = 0
    value, string = "", ""
    source=""
    if request.method == 'POST':
        source="/progress"
        f = request.files['hashfile']
        t = request.form['threads']
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
        f.save(filepath)
        start_time = time.time()
        filethread = filepath
        threads = t
        minerthread()
        res = returnResult()
        value = []
        for hashvalue, cracked in res.items():
            value.append([hashvalue,cracked.strip("\n")])
        
        timetocrack = (time.time() - start_time)    
        for row in value:
            for column in row:
                string+=column+" "
            string+="\n"
        if 'logged_in' in session:
            username = session["username"]
            filepath = os.path.join(app.config['UPLOAD_FOLDER'],"logs", username + '.txt')
            with open(filepath, "a") as userfile:
                st = ""
                for row in value:
                    st+= datetime.datetime.today().strftime("%d/%m/%Y %H:%M:%S")+" CF "+f.filename+" "
                    st += row[0]+" "+ hash_type(row[0])+" "+row[1]
                    st+="\n"
                userfile.write(st)
    if 'logged_in' in session:
        return render_template("concurrentthread.html", source=source,rows=value, download=string, time = timetocrack, logged_in=True, username = session['username'])
    return render_template("concurrentthread.html",source=source, rows=value, download=string, time = timetocrack,  logged_in=False)

xx = "-"
@app.route('/progress')
def progress():
    def generate():
        tosend = 0
        while tosend < 100:
            tosend = 0
            if xx!="-":
                val1,val2 = xx.split(" ")
                tosend = int((int(val1)/int(val2))*100)
                print(tosend)
            yield "data:" + str(tosend) + "\n\n"
            time.sleep(0.5)
    return Response(generate(), mimetype= 'text/event-stream')

@app.route('/logs')
def logs(): 
    table = []
    if 'logged_in' in session:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'],"logs", session["username"] + '.txt')
        
        with open(filepath, 'r' if os.path.exists(filepath) else 'w+') as userfile:
            for line in userfile:
                table.append(line.split(" "))
        print(os.path.join(basedir,filepath).replace('\\','/'))

        return render_template("logs.html", logged_in=True, username = session['username'],table=table) 
    return render_template("logs.html", logged_in=False)


@app.route('/downloadlogs')
def downloadlogs(): 
    filepath = os.path.join(app.config['UPLOAD_FOLDER'],"logs", session["username"] + '.txt')
    return send_file(filepath, as_attachment=True)

@app.route('/passwordstrength',methods = ['POST','GET'])
def passwordstrength(): 
    values = []
    score = 0
    readable_score = 0
    password = ""
    if request.method == 'POST':
        password = request.form['password']
        ans = findStrength(password)
        score = ans[0]
        readable_score = ans[1]
        values = ans[2]
    if 'logged_in' in session:
        return render_template("passwordstrength.html",ans=values, score = score, readable_score = readable_score, password=password, logged_in=True, username = session['username']) 
    return render_template("passwordstrength.html",ans=values, score = score, readable_score = readable_score, password=password, logged_in=False)

@app.route('/encrypt', methods = ['POST','GET'])
def encrypt():
    timetoenc = 0
    string = ""
    word_dict = None
    if request.method == 'POST':
        f = request.files['file']
        filepath = os.path.join(app.config['UPLOAD_FOLDER'],"wordlists", f.filename)
        f.save(filepath)
        start_time = time.time()
        word_dict = encrypt_all(filepath,get_type=True)
        timetoenc = (time.time() - start_time)
        for word, hash_dict in word_dict.items(): 
            print(hash_dict)
            for hash_value,hash_type in hash_dict.items():
                string+=word+" "+hash_type+" "+hash_value+"\n"
        
        if 'logged_in' in session:
            username = session["username"]
            filepath = os.path.join(app.config['UPLOAD_FOLDER'],"logs", username + '.txt')
            with open(filepath, "a") as userfile:
                st = ""
                for word, hash_dict in word_dict.items(): 
                    for hash_value,hash_type in hash_dict.items():
                        st+= datetime.datetime.today().strftime("%d/%m/%Y %H:%M:%S")+" EF "+f.filename+" "
                        st+=hash_value+" "+hash_type+" "+word+"\n"
                userfile.write(st)
    if 'logged_in' in session:
        return render_template("encrypt.html", dict=word_dict, download=string, time = timetoenc, logged_in=True, username = session['username'])
    return render_template("encrypt.html", dict=word_dict, download=string, time = timetoenc,  logged_in=False)


if __name__ == "__main__":
    app.run(debug=True)