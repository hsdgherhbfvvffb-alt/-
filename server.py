from flask import Flask, request, jsonify, session, redirect, render_template, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pathlib import Path
from functools import wraps
import sqlite3, secrets, os, subprocess, threading, zipfile, shutil, datetime, sys

ROOT=Path(__file__).resolve().parent
DATA=ROOT/"data"; SERVERS=DATA/"servers"; DB=DATA/"panel.sqlite3"
DATA.mkdir(exist_ok=True); SERVERS.mkdir(parents=True,exist_ok=True)
app=Flask(__name__,template_folder="templates")
app.secret_key=os.environ.get("FLASK_SECRET") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"]=100*1024*1024
app.config["SESSION_COOKIE_HTTPONLY"]=True
app.config["SESSION_COOKIE_SAMESITE"]="Lax"
running={}; lock=threading.RLock()

def connect():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def init_db():
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password_hash TEXT,is_admin INTEGER DEFAULT 0,plan TEXT DEFAULT 'free',max_servers INTEGER DEFAULT 2,expiry_days INTEGER DEFAULT 365,created_at TEXT);
        CREATE TABLE IF NOT EXISTS servers(id INTEGER PRIMARY KEY,folder TEXT UNIQUE,owner TEXT,title TEXT,type TEXT,port INTEGER,status TEXT DEFAULT 'Stopped',startup_file TEXT,created_at TEXT);
        CREATE TABLE IF NOT EXISTS plans(id TEXT PRIMARY KEY,name TEXT,price INTEGER,storage INTEGER,ram INTEGER,cpu REAL,max_servers INTEGER);
        """)
        if not c.execute("SELECT id FROM users WHERE is_admin=1").fetchone():
            pw=secrets.token_urlsafe(14)
            c.execute("INSERT INTO users(username,password_hash,is_admin,plan,created_at) VALUES(?,?,1,'admin',?)",
                      ("admin",generate_password_hash(pw),datetime.datetime.now().isoformat()))
            print("\n"+"="*54+"\nZIAD HOST ADMIN (shown only once)\nUsername: admin\nPassword: "+pw+"\n"+"="*54+"\n")
        c.execute("INSERT OR IGNORE INTO plans VALUES('free','مجاني',0,512000,256,0.5,2)")
def me():
    name=session.get("username")
    if not name:return None
    with connect() as c:
        r=c.execute("SELECT * FROM users WHERE username=?",(name,)).fetchone()
        return dict(r) if r else None
def auth(f):
    @wraps(f)
    def w(*a,**k):
        if not me():return jsonify(success=False,message="سجل الدخول أولاً"),401
        return f(*a,**k)
    return w
def admin(f):
    @wraps(f)
    def w(*a,**k):
        u=me()
        if not u or not u["is_admin"]:return jsonify(success=False,message="غير مصرح"),403
        return f(*a,**k)
    return w
def body():return request.get_json(silent=True) or {}
def get_server(folder):
    if not folder or folder in (".","..") or "/" in folder or "\\" in folder:return None
    u=me()
    with connect() as c:r=c.execute("SELECT * FROM servers WHERE folder=?",(folder,)).fetchone()
    if not r:return None
    s=dict(r)
    return s if u and (u["is_admin"] or s["owner"]==u["username"]) else None
def spath(folder):
    p=(SERVERS/folder).resolve()
    if SERVERS.resolve() not in p.parents:raise ValueError()
    p.mkdir(parents=True,exist_ok=True);return p
def safe_file(folder,name):
    s=get_server(folder)
    if not s:return None,None
    name=name.replace("\\","/")
    if name.startswith("/") or ".." in Path(name).parts:return None,None
    p=(spath(folder)/name).resolve()
    if spath(folder).resolve() not in p.parents:return None,None
    return s,p
@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"]="nosniff";r.headers["X-Frame-Options"]="SAMEORIGIN";return r
@app.get("/")
def home():
    u=me();return redirect("/login" if not u else ("/admin" if u["is_admin"] else "/dashboard"))
@app.get("/login")
def login_page():return render_template("login.html")
@app.get("/dashboard")
def dash():return render_template("index.html") if me() and not me()["is_admin"] else redirect("/login")
@app.get("/admin")
def admin_page():return render_template("admin_panel.html") if me() and me()["is_admin"] else redirect("/login")
@app.post("/api/login")
def login():
    b=body()
    with connect() as c:r=c.execute("SELECT * FROM users WHERE username=?",(str(b.get("username","")).strip(),)).fetchone()
    if not r or not check_password_hash(r["password_hash"],str(b.get("password",""))):return jsonify(success=False,message="بيانات الدخول غير صحيحة"),401
    session.clear();session["username"]=r["username"]
    return jsonify(success=True,is_admin=bool(r["is_admin"]),redirect="/admin" if r["is_admin"] else "/dashboard")
@app.post("/api/register")
def register():
    b=body();name=str(b.get("username","")).strip();pw=str(b.get("password",""))
    if len(name)<3 or len(name)>32 or not name.replace("_","").isalnum():return jsonify(success=False,message="اسم المستخدم غير صالح")
    if len(pw)<8:return jsonify(success=False,message="كلمة المرور يجب أن تكون 8 أحرف على الأقل")
    try:
        with connect() as c:c.execute("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",(name,generate_password_hash(pw),datetime.datetime.now().isoformat()))
        return jsonify(success=True,message="تم إنشاء الحساب")
    except sqlite3.IntegrityError:return jsonify(success=False,message="اسم المستخدم موجود")
@app.get("/api/current_user")
def current():
    u=me();return jsonify(success=bool(u),username=u["username"] if u else None,is_admin=bool(u and u["is_admin"]))
@app.post("/api/logout")
def logout():session.clear();return jsonify(success=True)
@app.get("/api/system/metrics")
@auth
def metrics():
    try:
        import psutil
        cpu=psutil.cpu_percent();mem=psutil.virtual_memory().percent
    except Exception:cpu=0;mem=0
    return jsonify(cpu=cpu,memory=mem,users=0,servers=len(list(SERVERS.iterdir())),disk=0)
@app.get("/api/servers")
@auth
def servers():
    u=me();owner=request.args.get("user")
    with connect() as c:
        if u["is_admin"] and owner:r=c.execute("SELECT * FROM servers WHERE owner=?",(owner,)).fetchall()
        elif u["is_admin"]:r=c.execute("SELECT * FROM servers").fetchall()
        else:r=c.execute("SELECT * FROM servers WHERE owner=?",(u["username"],)).fetchall()
    return jsonify([dict(x) for x in r])
@app.post("/api/server/add")
@auth
def add_server():
    u=me();b=body()
    with connect() as c:
        count=c.execute("SELECT COUNT(*) FROM servers WHERE owner=?",(u["username"],)).fetchone()[0]
        if not u["is_admin"] and count>=u["max_servers"]:return jsonify(success=False,message="وصلت للحد الأقصى للسيرفرات")
        folder="srv_"+secrets.token_hex(5);title=str(b.get("name") or b.get("title") or "New Server")[:60]
        typ=str(b.get("type") or "Python")
        (SERVERS/folder).mkdir()
        c.execute("INSERT INTO servers(folder,owner,title,type,created_at) VALUES(?,?,?,?,?)",(folder,u["username"],title,typ,datetime.datetime.now().isoformat()))
    return jsonify(success=True,folder=folder,message="تم إنشاء السيرفر")
@app.post("/api/user/upgrade")
@auth
def upgrade():return jsonify(success=False,message="الترقية غير مفعلة في النسخة المحلية")
@app.post("/api/create_api_key")
@auth
def api_key():return jsonify(success=True,key=secrets.token_urlsafe(32))
@app.get("/api/plans")
@auth
def plans():
    with connect() as c:r=c.execute("SELECT * FROM plans").fetchall()
    return jsonify([dict(x) for x in r])
@app.get("/api/admin/users")
@admin
def users():
    with connect() as c:r=c.execute("SELECT id,username,is_admin,plan,max_servers,expiry_days,created_at FROM users").fetchall()
    return jsonify([dict(x) for x in r])
@app.post("/api/admin/create-user")
@admin
def create_user():
    b=body();name=str(b.get("username","")).strip();pw=str(b.get("password",""))
    if len(name)<3 or len(pw)<8:return jsonify(success=False,message="تحقق من البيانات")
    try:
        with connect() as c:c.execute("INSERT INTO users(username,password_hash,max_servers,expiry_days,created_at) VALUES(?,?,?,?,?)",(name,generate_password_hash(pw),int(b.get("maxServers",2)),int(b.get("expiryDays",365)),datetime.datetime.now().isoformat()))
        return jsonify(success=True)
    except sqlite3.IntegrityError:return jsonify(success=False,message="المستخدم موجود")
@app.post("/api/admin/delete-user")
@admin
def delete_user():
    name=str(body().get("username",""))
    if name=="admin":return jsonify(success=False,message="لا يمكن حذف المسؤول")
    with connect() as c:c.execute("DELETE FROM users WHERE username=? AND is_admin=0",(name,))
    return jsonify(success=True)
@app.post("/api/admin/add-plan")
@admin
def add_plan():
    b=body();pid=str(b.get("id") or secrets.token_hex(3))
    with connect() as c:c.execute("INSERT OR REPLACE INTO plans VALUES(?,?,?,?,?,?,?)",(pid,str(b.get("name","Plan")),int(b.get("price",0)),int(b.get("storage",512000)),int(b.get("ram",256)),float(b.get("cpu",.5)),int(b.get("max_servers",2))))
    return jsonify(success=True)
@app.post("/api/server/action/<folder>/<action>")
@auth
def server_action(folder,action):
    s=get_server(folder)
    if not s:return jsonify(success=False,message="السيرفر غير موجود"),404
    with lock:
        p=running.get(folder)
        if action=="delete":
            if p and p.poll() is None:p.terminate()
            running.pop(folder,None);shutil.rmtree(spath(folder),ignore_errors=True)
            with connect() as c:c.execute("DELETE FROM servers WHERE folder=?",(folder,))
            return jsonify(success=True)
        if action in ("stop","restart") and p and p.poll() is None:p.terminate();p.wait(timeout=3)
        if action in ("start","restart"):
            base=spath(folder)
            filename=(s.get("startup_file") or "").strip()
            # Run any Python file regardless of its filename. If the saved file
            # is missing, choose the first available .py file in the server folder.
            saved_target=(base/filename).resolve() if filename else None
            if not filename or base.resolve() not in saved_target.parents or not saved_target.is_file():
                candidates=sorted(
                    (x for x in base.rglob("*.py")
                     if x.is_file() and "node_modules" not in x.parts and "__pycache__" not in x.parts
                     and x.name != "console.log"),
                    key=lambda x: (len(x.relative_to(base).parts), x.relative_to(base).as_posix().lower())
                )
                if candidates:
                    target=candidates[0]
                    filename=target.relative_to(base).as_posix()
                    with connect() as c:
                        c.execute("UPDATE servers SET startup_file=? WHERE folder=?",(filename,folder))
                else:
                    return jsonify(success=False,message="لم يتم العثور على أي ملف Python بصيغة .py داخل ملفات الخادم. ارفع ملف البوت أولاً."),400
            target=(base/filename).resolve()
            if base.resolve() not in target.parents or not target.is_file():
                return jsonify(success=False,message=f"ملف التشغيل المحدد غير موجود: {filename}. افتح الملفات وارفع الملف الصحيح ثم اختره من الإعدادات."),400
            cmd=[sys.executable,str(target)] if target.suffix==".py" else ["node",str(target)]
            try:
                log=open(spath(folder)/"console.log","ab")
                proc=subprocess.Popen(cmd,cwd=spath(folder),stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
                running[folder]=proc
            except Exception as e:return jsonify(success=False,message=str(e))
        with connect() as c:c.execute("UPDATE servers SET status=? WHERE folder=?",("Running" if action in ("start","restart") else "Stopped",folder))
    return jsonify(success=True,message="تم تنفيذ الأمر")
@app.get("/api/server/stats/<folder>")
@auth
def server_stats(folder):
    s=get_server(folder)
    if not s:return jsonify(success=False),404
    p=running.get(folder);log=spath(folder)/"console.log"
    return jsonify(status="Running" if p and p.poll() is None else "Stopped",console=log.read_text(errors="replace")[-12000:] if log.exists() else "")
@app.get("/api/files/list/<folder>")
@auth
def list_files(folder):
    s=get_server(folder)
    if not s:return jsonify([])
    out=[]
    base=spath(folder)
    for p in base.rglob("*"):
        if any(part in ("__pycache__",".git","node_modules") for part in p.relative_to(base).parts):
            continue
        out.append({"name":p.relative_to(base).as_posix(),"is_dir":p.is_dir(),"size":p.stat().st_size if p.is_file() else 0})
    return jsonify(out)
@app.get("/api/files/content/<folder>/<path:name>")
@auth
def file_content(folder,name):
    s,p=safe_file(folder,name)
    if not p or not p.is_file():return jsonify(success=False),404
    try:return jsonify(content=p.read_text(encoding="utf-8"))
    except UnicodeDecodeError:return jsonify(content="[ملف غير نصي]")
@app.post("/api/files/save/<folder>/<path:name>")
@auth
def save_file(folder,name):
    s,p=safe_file(folder,name)
    if not p:return jsonify(success=False),404
    p.parent.mkdir(parents=True,exist_ok=True);p.write_text(str(body().get("content","")),encoding="utf-8")
    return jsonify(success=True)
@app.post("/api/files/create/<folder>")
@auth
def create_file(folder):
    b=body();name=secure_filename(str(b.get("filename","")))
    if not name:return jsonify(success=False),400
    s,p=safe_file(folder,name)
    if not p:return jsonify(success=False),404
    p.parent.mkdir(parents=True,exist_ok=True)
    if name.endswith("/"):p.mkdir(exist_ok=True)
    else:p.write_text(str(b.get("content","")),encoding="utf-8")
    return jsonify(success=True)
@app.post("/api/files/delete/<folder>")
@auth
def delete_files(folder):
    b=body();s=get_server(folder)
    if not s:return jsonify(success=False),404
    for n in b.get("names",[]):
        ss,p=safe_file(folder,str(n))
        if p and p.exists():
            shutil.rmtree(p) if p.is_dir() else p.unlink()
    return jsonify(success=True)
@app.post("/api/files/rename/<folder>")
@auth
def rename_file(folder):
    b=body();_,a=safe_file(folder,str(b.get("old_name","")));_,z=safe_file(folder,str(b.get("new_name","")))
    if not a or not z or not a.exists():return jsonify(success=False),400
    a.rename(z);return jsonify(success=True)
@app.post("/api/files/upload/<folder>")
@auth
def upload(folder):
    s=get_server(folder)
    if not s:return jsonify(success=False),404
    for f in request.files.getlist("files[]"):
        name=secure_filename(f.filename)
        if name:f.save(spath(folder)/name)
    return jsonify(success=True)
@app.post("/api/files/unzip/<folder>/<path:name>")
@auth
def unzip(folder,name):
    _,p=safe_file(folder,name)
    if not p or not p.is_file():return jsonify(success=False),404
    dest=spath(folder)
    try:
        with zipfile.ZipFile(p) as z:
            for item in z.infolist():
                target=(dest/item.filename).resolve()
                if dest.resolve() not in target.parents:continue
                z.extract(item,dest)
        return jsonify(success=True)
    except Exception as e:return jsonify(success=False,message=str(e))
@app.post("/api/server/set-startup/<folder>")
@auth
def set_startup(folder):
    b=body();name=str(b.get("filename","")).replace("\\\\","/").strip()
    _,p=safe_file(folder,name)
    if not p or not p.is_file() or p.suffix not in (".py",".js"):return jsonify(success=False,message="ملف التشغيل غير صالح أو غير موجود"),400
    with connect() as c:c.execute("UPDATE servers SET startup_file=? WHERE folder=?",(name,folder))
    return jsonify(success=True)
@app.post("/api/server/install/<folder>")
@auth
def install(folder):
    s=get_server(folder)
    if not s:return jsonify(success=False),404
    req=spath(folder)/"requirements.txt"
    if not req.exists():return jsonify(success=False,message="لا يوجد requirements.txt")
    try:
        subprocess.run([sys.executable,"-m","pip","install","-r",str(req)],cwd=spath(folder),timeout=180,check=True,capture_output=True,text=True)
        return jsonify(success=True,message="تم تثبيت المكتبات")
    except Exception as e:return jsonify(success=False,message="فشل التثبيت: "+str(e)[:250])
if __name__=="__main__":
    init_db()
    host=os.environ.get("HOST","127.0.0.1");port=int(os.environ.get("PORT","5000"))
    print(f"ZIAD HOST running: http://127.0.0.1:{port}")
    app.run(host=host,port=port,debug=False)
