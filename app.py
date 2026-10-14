from flask import Flask, request, jsonify, session, send_from_directory, render_template, send_file
import sqlite3, os, datetime, uuid
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

BASE=os.path.dirname(__file__)
DATA_DIR=os.environ.get("DATA_DIR", os.path.join(BASE,"data"))
os.makedirs(DATA_DIR, exist_ok=True)
DB=os.path.join(DATA_DIR,"database.db")
UPLOAD=os.path.join(DATA_DIR,"uploads")
os.makedirs(UPLOAD,exist_ok=True)
app=Flask(__name__)
app.secret_key=os.environ.get("SECRET_KEY", "change-this-secret-key-before-production")
app.config.update(
    MAX_CONTENT_LENGTH=10*1024*1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE","0") == "1"
)

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def init():
    c=db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password TEXT,role TEXT,active INTEGER DEFAULT 1);
    CREATE TABLE IF NOT EXISTS landings(id INTEGER PRIMARY KEY,landing_no TEXT UNIQUE,landing_date TEXT,landing_time TEXT,ship_name TEXT,ship_no TEXT,trip_no TEXT,catch_type TEXT,total_qty REAL,notes TEXT,created_by TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS fish(id INTEGER PRIMARY KEY,landing_id INTEGER,fish_name TEXT,quantity REAL);
    CREATE TABLE IF NOT EXISTS inspectors(id INTEGER PRIMARY KEY,landing_id INTEGER,inspector_name TEXT,signature TEXT);
    CREATE TABLE IF NOT EXISTS attachments(id INTEGER PRIMARY KEY,landing_id INTEGER,filename TEXT,original_name TEXT,uploaded_at TEXT);
    CREATE TABLE IF NOT EXISTS ships(id INTEGER PRIMARY KEY,ship_no TEXT UNIQUE,ship_name TEXT,owner_name TEXT,license_no TEXT,notes TEXT);
    CREATE TABLE IF NOT EXISTS landing_signatures(id INTEGER PRIMARY KEY,landing_id INTEGER,inspector_name TEXT,signature_text TEXT,signed_at TEXT);
    CREATE TABLE IF NOT EXISTS landing_status(id INTEGER PRIMARY KEY,landing_id INTEGER UNIQUE,status TEXT,updated_by TEXT,updated_at TEXT);
    CREATE TABLE IF NOT EXISTS delegations(id INTEGER PRIMARY KEY AUTOINCREMENT,delegate_user_id INTEGER,start_at TEXT,end_at TEXT,granted_by INTEGER,active INTEGER DEFAULT 1);
    CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,username TEXT,action TEXT NOT NULL,target_type TEXT,target_id INTEGER,details TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    """)
    try: c.execute("ALTER TABLE users ADD COLUMN active INTEGER DEFAULT 1")
    except sqlite3.OperationalError: pass
    try: c.execute("ALTER TABLE inspectors ADD COLUMN signature TEXT")
    except sqlite3.OperationalError: pass
    if c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]==0:
        c.execute("INSERT INTO users(username,password,role,active) VALUES(?,?,?,1)",("admin",generate_password_hash("admin123"),"admin"))
        c.execute("INSERT INTO users(username,password,role,active) VALUES(?,?,?,1)",("inspector",generate_password_hash("inspect123"),"inspector"))
        c.execute("INSERT INTO users(username,password,role,active) VALUES(?,?,?,1)",("viewer",generate_password_hash("view123"),"viewer"))
    c.commit(); c.close()
init()

def current_user():
    username=session.get("username")
    if not username: return None
    c=db(); row=c.execute("SELECT * FROM users WHERE username=? AND COALESCE(active,1)=1",(username,)).fetchone()
    if not row: c.close(); return None
    u=dict(row); now=datetime.datetime.now().isoformat(timespec="minutes")
    d=c.execute("SELECT * FROM delegations WHERE delegate_user_id=? AND active=1 AND start_at<=? AND end_at>=? ORDER BY id DESC LIMIT 1",(u["id"],now,now)).fetchone()
    c.close()
    if d and u["role"] != "admin":
        u["original_role"]=u["role"]; u["role"]="admin"; u["delegation_id"]=d["id"]
    return u

def current(): return current_user()

def auth(fn):
    @wraps(fn)
    def w(*a,**k):
        u=current()
        if not u: return jsonify({"ok":False,"error":"غير مسجل الدخول"}),401
        return fn(*a,**k)
    return w
def admin(fn):
    @wraps(fn)
    def w(*a,**k):
        u=current()
        if not u or u["role"]!="admin": return jsonify({"ok":False,"error":"صلاحية المدير مطلوبة"}),403
        return fn(*a,**k)
    return w



def write_audit(action, target_type=None, target_id=None, details=None):
    u=current_user()
    if not u:
        return
    conn=db()
    conn.execute("""INSERT INTO audit_logs
        (user_id,username,action,target_type,target_id,details)
        VALUES(?,?,?,?,?,?)""",
        (u['id'],u['username'],action,target_type,target_id,details or ''))
    try:
        conn.execute("ALTER TABLE users ADD COLUMN active INTEGER DEFAULT 1")
    except Exception:
        pass
    conn.commit()
    conn.close()





@app.post('/api/users/<int:uid>/toggle')
def toggle_user(uid):
    u=current_user()
    if not u or u['role']!='admin':
        return jsonify({'error':'غير مصرح'}),403
    if uid==u['id']:
        return jsonify({'error':'لا يمكن تعطيل حساب المدير الحالي'}),400
    conn=db()
    row=conn.execute("SELECT id,username,active FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        conn.close(); return jsonify({'error':'المستخدم غير موجود'}),404
    new_status=0 if row['active'] else 1
    conn.execute("UPDATE users SET active=? WHERE id=?", (new_status,uid))
    conn.commit(); conn.close()
    try: write_audit('تغيير حالة حساب','user',uid,('تفعيل' if new_status else 'تعطيل')+' الحساب '+row['username'])
    except Exception: pass
    return jsonify({'ok':True,'active':new_status})

@app.post('/api/users/<int:uid>/reset-password')
def reset_user_password(uid):
    u=current_user()
    if not u or u['role']!='admin':
        return jsonify({'error':'غير مصرح'}),403
    data=request.json or {}
    new_password=data.get('new_password') or ''
    if len(new_password)<8:
        return jsonify({'error':'كلمة المرور يجب ألا تقل عن 8 أحرف'}),400
    conn=db()
    row=conn.execute("SELECT id,username FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        conn.close(); return jsonify({'error':'المستخدم غير موجود'}),404
    conn.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(new_password),uid))
    conn.commit(); conn.close()
    try: write_audit('إعادة تعيين كلمة مرور','user',uid,'إعادة تعيين كلمة مرور المستخدم '+row['username'])
    except Exception: pass
    return jsonify({'ok':True})

@app.get('/api/admin/summary')
def admin_summary():
    u=current_user()
    if not u or u['role']!='admin':
        return jsonify({'error':'غير مصرح'}),403
    conn=db()
    total_users=conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    active_users=conn.execute("SELECT COUNT(*) FROM users WHERE active=1").fetchone()[0]
    total_landings=conn.execute("SELECT COUNT(*) FROM landings").fetchone()[0]
    pending=conn.execute("""SELECT COUNT(*) FROM landing_status WHERE status='مراجعة'""").fetchone()[0]
    approved=conn.execute("""SELECT COUNT(*) FROM landing_status WHERE status='معتمد'""").fetchone()[0]
    active_delegations=conn.execute("SELECT COUNT(*) FROM delegations WHERE active=1").fetchone()[0]
    conn.close()
    return jsonify({'total_users':total_users,'active_users':active_users,
                    'total_landings':total_landings,'pending':pending,
                    'approved':approved,'active_delegations':active_delegations})
@app.post('/api/login')
def api_login():
    data=request.json or {}
    username=(data.get('username') or '').strip()
    password=data.get('password') or ''
    conn=db()
    row=conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not row or (('active' in row.keys()) and row['active']==0) or not check_password_hash(row['password'], password):
        return jsonify({'error':'اسم المستخدم أو كلمة المرور غير صحيحة'}),401
    session.clear()
    session['username']=row['username']
    session.permanent=True
    return jsonify({'ok':True,'username':row['username'],'role':row['role']})

@app.post('/api/logout')
def api_logout():
    session.clear()
    return jsonify({'ok':True})

@app.get('/api/me')
def api_me():
    u=current_user()
    if not u:
        return jsonify({'authenticated':False})
    return jsonify({'authenticated':True,'username':u['username'],'role':u['role'],
                    'original_role':u.get('original_role'),'delegation_id':u.get('delegation_id')})

@app.post('/api/change-password')
def change_password():
    u=current_user()
    if not u: return jsonify({'error':'غير مصرح'}),401
    data=request.json or {}
    old=data.get('old_password') or ''
    new=data.get('new_password') or ''
    if len(new)<8:
        return jsonify({'error':'كلمة المرور الجديدة يجب ألا تقل عن 8 أحرف'}),400
    conn=db()
    row=conn.execute("SELECT * FROM users WHERE id=?", (u['id'],)).fetchone()
    if not row or not check_password_hash(row['password'], old):
        conn.close()
        return jsonify({'error':'كلمة المرور الحالية غير صحيحة'}),400
    conn.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(new),u['id']))
    conn.commit(); conn.close()
    return jsonify({'ok':True})

@app.post('/api/audit-test')
def audit_test():
    u=current_user()
    if not u:
        return jsonify({'error':'غير مصرح'}),403
    write_audit('اختبار سجل العمليات','system',None,'تم تسجيل العملية بنجاح')
    return jsonify({'ok':True})
@app.get('/api/audit-logs')
def audit_logs():
    u=current_user()
    if not u or u['role']!='admin':
        return jsonify({'error':'غير مصرح'}),403
    q=(request.args.get('q') or '').strip()
    conn=db()
    if q:
        rows=conn.execute("""SELECT * FROM audit_logs
            WHERE username LIKE ? OR action LIKE ? OR details LIKE ?
            ORDER BY id DESC LIMIT 500""",(f'%{q}%',f'%{q}%',f'%{q}%')).fetchall()
    else:
        rows=conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 500").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.get('/api/delegations')
def get_delegations():
    u = current_user()
    if not u or u['role'] != 'admin':
        return jsonify({'error':'غير مصرح'}), 403
    conn = db()
    rows = conn.execute("""
        SELECT d.*, u.username AS delegate_username, g.username AS granted_by_username
        FROM delegations d
        JOIN users u ON u.id=d.delegate_user_id
        JOIN users g ON g.id=d.granted_by
        ORDER BY d.id DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.post('/api/delegations')
def create_delegation():
    u = current_user()
    if not u or u['role'] != 'admin':
        return jsonify({'error':'غير مصرح'}), 403
    data = request.json or {}
    username = (data.get('username') or '').strip()
    start_at = (data.get('start_at') or '').strip()
    end_at = (data.get('end_at') or '').strip()
    if not username or not start_at or not end_at:
        return jsonify({'error':'أكمل بيانات التفويض'}), 400
    if end_at <= start_at:
        return jsonify({'error':'وقت نهاية التفويض يجب أن يكون بعد وقت البداية'}), 400
    conn = db()
    target = conn.execute("SELECT id, username, role FROM users WHERE username=?", (username,)).fetchone()
    if not target:
        conn.close()
        return jsonify({'error':'المستخدم غير موجود'}), 404
    if target['role'] not in ('inspector','admin'):
        conn.close()
        return jsonify({'error':'يمكن منح التفويض للمفتشين فقط'}), 400
    conn.execute("UPDATE delegations SET active=0 WHERE delegate_user_id=? AND active=1", (target['id'],))
    conn.execute(
        "INSERT INTO delegations(delegate_user_id,start_at,end_at,granted_by,active) VALUES(?,?,?,?,1)",
        (target['id'], start_at, end_at, u['id'])
    )
    conn.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        action TEXT NOT NULL,
        target_type TEXT,
        target_id INTEGER,
        details TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    conn.close()
    return jsonify({'ok':True})

@app.post('/api/delegations/<int:did>/revoke')
def revoke_delegation(did):
    u = current_user()
    if not u or u['role'] != 'admin':
        return jsonify({'error':'غير مصرح'}), 403
    conn = db()
    conn.execute("UPDATE delegations SET active=0 WHERE id=?", (did,))
    conn.commit()
    conn.close()
    return jsonify({'ok':True})

@app.get('/api/my-delegation')
def my_delegation():
    u = current_user()
    if not u:
        return jsonify({'error':'غير مصرح'}), 403
    conn = db()
    row = conn.execute("""
        SELECT d.*, g.username AS granted_by_username
        FROM delegations d JOIN users g ON g.id=d.granted_by
        WHERE d.delegate_user_id=? AND d.active=1
        ORDER BY d.id DESC LIMIT 1
    """, (u['id'],)).fetchone()
    conn.close()
    return jsonify(dict(row) if row else None)

@app.before_request
def identify():
    request.user=current_user()

@app.get("/manifest.webmanifest")
def pwa_manifest():
    return send_from_directory(os.path.join(BASE, "static"), "manifest.webmanifest", mimetype="application/manifest+json")

@app.get("/service-worker.js")
def pwa_service_worker():
    response = send_from_directory(os.path.join(BASE, "static"), "service-worker.js", mimetype="application/javascript")
    response.headers["Service-Worker-Allowed"] = "/"
    response.headers["Cache-Control"] = "no-cache"
    return response

@app.route("/")
def home(): return render_template("index.html")

@app.get("/api/landings")
@auth
def landings():
    q=request.args.get("q","").strip(); df=request.args.get("from",""); dt=request.args.get("to","")
    sql="SELECT * FROM landings WHERE 1=1"; p=[]
    if q: sql+=" AND (landing_no LIKE ? OR ship_name LIKE ? OR ship_no LIKE ?)"; p += [f"%{q}%"]*3
    if df: sql+=" AND landing_date>=?"; p.append(df)
    if dt: sql+=" AND landing_date<=?"; p.append(dt)
    sql+=" ORDER BY id DESC"
    c=db(); rows=c.execute(sql,p).fetchall()
    out=[]
    for r in rows:
        x=dict(r); x["fish"]=[dict(z) for z in c.execute("SELECT fish_name,quantity FROM fish WHERE landing_id=?",(r["id"],))]
        x["inspectors"]=[z["inspector_name"] for z in c.execute("SELECT inspector_name FROM inspectors WHERE landing_id=?",(r["id"],))]
        x["attachments"]=[dict(z) for z in c.execute("SELECT id,original_name,filename,uploaded_at FROM attachments WHERE landing_id=?",(r["id"],))]
        st=c.execute("SELECT status FROM landing_status WHERE landing_id=?",(r["id"],)).fetchone()
        x["status"]=st["status"] if st else "مسودة"
        x["signatures"]=[dict(z) for z in c.execute("SELECT inspector_name,signature_text,signed_at FROM landing_signatures WHERE landing_id=?",(r["id"],))]
        out.append(x)
    c.close(); return jsonify(out)

@app.post("/api/landings")
@auth
def add_landing():
    d=request.json or {}; c=db()
    n=c.execute("SELECT COUNT(*) n FROM landings").fetchone()["n"]+1
    no=d.get("landing_no") or f"DQM-{n:05d}"
    now=datetime.datetime.now().isoformat(timespec="seconds")
    try:
        cur=c.execute("""INSERT INTO landings(landing_no,landing_date,landing_time,ship_name,ship_no,trip_no,catch_type,total_qty,notes,created_by,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)""",(no,d.get("landing_date"),d.get("landing_time"),d.get("ship_name"),d.get("ship_no"),d.get("trip_no"),d.get("catch_type"),float(d.get("total_qty") or 0),d.get("notes"),current()["username"],now))
        lid=cur.lastrowid
        for f in d.get("fish",[]):
            if f.get("fish_name"): c.execute("INSERT INTO fish(landing_id,fish_name,quantity) VALUES(?,?,?)",(lid,f["fish_name"],float(f.get("quantity") or 0)))
        for name in d.get("inspectors",[]):
            if name.strip(): c.execute("INSERT INTO inspectors(landing_id,inspector_name) VALUES(?,?)",(lid,name.strip()))
        c.execute("INSERT OR REPLACE INTO landing_status(landing_id,status,updated_by,updated_at) VALUES(?,?,?,?)",(lid,"مسودة",current()["username"],now))
        c.commit()
    except Exception as e:
        c.rollback(); c.close(); return jsonify({"ok":False,"error":str(e)}),400
    c.close(); return jsonify({"ok":True,"id":lid,"landing_no":no})

@app.post("/api/landings/<int:lid>/attachments")
@auth
def upload(lid):
    c=db()
    if not c.execute("SELECT id FROM landings WHERE id=?",(lid,)).fetchone(): c.close(); return jsonify({"error":"الإنزال غير موجود"}),404
    files=request.files.getlist("files"); saved=[]
    allowed={".jpg",".jpeg",".png",".pdf"}
    for f in files:
        ext=os.path.splitext(f.filename or "")[1].lower()
        if ext not in allowed: continue
        safe=f"{uuid.uuid4().hex}{ext}"; f.save(os.path.join(UPLOAD,safe))
        c.execute("INSERT INTO attachments(landing_id,filename,original_name,uploaded_at) VALUES(?,?,?,?)",(lid,safe,f.filename,datetime.datetime.now().isoformat(timespec="seconds")))
        saved.append(f.filename)
    c.commit(); c.close(); return jsonify({"ok":True,"files":saved})

@app.get("/uploads/<name>")
def uploaded(name): return send_from_directory(UPLOAD,name)

@app.get("/api/users")
@admin
def users():
    c=db(); x=[dict(r) for r in c.execute("SELECT id,username,role FROM users ORDER BY id").fetchall()]; c.close(); return jsonify(x)

@app.post("/api/users")
@admin
def add_user():
    d=request.json or {}
    if not d.get("username") or len(d.get("password",""))<6 or d.get("role") not in ("admin","inspector","viewer"):
        return jsonify({"ok":False,"error":"بيانات الموظف غير مكتملة"}),400
    c=db()
    try:
        c.execute("INSERT INTO users(username,password,role) VALUES(?,?,?)",(d["username"],generate_password_hash(d["password"]),d["role"])); c.commit()
    except sqlite3.IntegrityError: c.close(); return jsonify({"ok":False,"error":"اسم المستخدم موجود"}),400
    c.close(); return jsonify({"ok":True})

@app.get("/api/landings/<int:lid>/pdf")
@auth
def landing_pdf(lid):
    c=db(); r=c.execute("SELECT * FROM landings WHERE id=?",(lid,)).fetchone()
    if not r: c.close(); return jsonify({"error":"المحضر غير موجود"}),404
    fishrows=c.execute("SELECT fish_name,quantity FROM fish WHERE landing_id=?",(lid,)).fetchall()
    inspectors=[z["inspector_name"] for z in c.execute("SELECT inspector_name FROM inspectors WHERE landing_id=?",(lid,)).fetchall()]
    c.close()
    path=os.path.join(BASE,f"report_{lid}.pdf")
    font_path="/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    bold_path="/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
    if os.path.exists(font_path):
        pdfmetrics.registerFont(TTFont("Arabic",font_path))
        if os.path.exists(bold_path): pdfmetrics.registerFont(TTFont("ArabicBold",bold_path))
        font="Arabic"; bold="ArabicBold" if os.path.exists(bold_path) else "Arabic"
    else: font="Helvetica"; bold="Helvetica-Bold"
    styles=getSampleStyleSheet()
    styles.add(ParagraphStyle(name="AR",fontName=font,fontSize=10,leading=15,alignment=2))
    styles.add(ParagraphStyle(name="ARB",fontName=bold,fontSize=14,leading=18,alignment=2))
    doc=SimpleDocTemplate(path,pagesize=A4,rightMargin=35,leftMargin=35,topMargin=35,bottomMargin=35)
    story=[Paragraph("سلطنة عُمان",styles["ARB"]),Paragraph("الوسطى – ميناء الصيد البحري",styles["ARB"]),Paragraph("وحدة التفتيش",styles["ARB"]),Spacer(1,12),Paragraph("محضر تسجيل إنزال الأسماك",styles["ARB"]),Spacer(1,12)]
    data=[[Paragraph("<b>البيان</b>",styles["AR"]),Paragraph("<b>التفاصيل</b>",styles["AR"])],
          [Paragraph("رقم المحضر",styles["AR"]),Paragraph(str(r["landing_no"] or ""),styles["AR"])],
          [Paragraph("التاريخ / الوقت",styles["AR"]),Paragraph(f'{r["landing_date"] or ""} / {r["landing_time"] or ""}',styles["AR"])],
          [Paragraph("اسم السفينة",styles["AR"]),Paragraph(str(r["ship_name"] or ""),styles["AR"])],
          [Paragraph("رقم السفينة",styles["AR"]),Paragraph(str(r["ship_no"] or ""),styles["AR"])],
          [Paragraph("رقم الرحلة",styles["AR"]),Paragraph(str(r["trip_no"] or ""),styles["AR"])],
          [Paragraph("نوع المصيد",styles["AR"]),Paragraph(str(r["catch_type"] or ""),styles["AR"])],
          [Paragraph("إجمالي الكمية",styles["AR"]),Paragraph(f'{r["total_qty"] or 0} كجم',styles["AR"])]]
    t=Table(data,colWidths=[150,350]); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),.6,colors.grey),("VALIGN",(0,0),(-1,-1),"MIDDLE"),("BACKGROUND",(0,0),(-1,0),colors.lightgrey)])); story.append(t)
    story += [Spacer(1,15),Paragraph("تفاصيل الأسماك",styles["ARB"])]
    fd=[[Paragraph("<b>نوع السمك</b>",styles["AR"]),Paragraph("<b>الكمية (كجم)</b>",styles["AR"])]]
    fd += [[Paragraph(str(x["fish_name"]),styles["AR"]),Paragraph(str(x["quantity"]),styles["AR"])] for x in fishrows]
    if len(fd)==1: fd.append([Paragraph("لا توجد تفاصيل",styles["AR"]),Paragraph("0",styles["AR"])])
    ft=Table(fd,colWidths=[300,200]); ft.setStyle(TableStyle([("GRID",(0,0),(-1,-1),.6,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.lightgrey)])); story.append(ft)
    story += [Spacer(1,15),Paragraph("المفتشون: "+("، ".join(inspectors) if inspectors else "غير محدد"),styles["AR"]),
              Spacer(1,8),Paragraph("الملاحظات: "+str(r["notes"] or ""),styles["AR"]),Spacer(1,55),
              Paragraph("توقيع المفتش: __________________________",styles["AR"]),
              Spacer(1,18),Paragraph("اعتماد المسؤول: ________________________",styles["AR"])]
    doc.build(story)
    return send_file(path,as_attachment=True,download_name=f'{r["landing_no"]}.pdf',mimetype="application/pdf")

@app.post("/api/landings/<int:lid>/delete")
@admin
def delete_landing(lid):
    c=db()
    if not c.execute("SELECT id FROM landings WHERE id=?",(lid,)).fetchone():
        c.close(); return jsonify({"ok":False,"error":"المحضر غير موجود"}),404
    c.execute("DELETE FROM fish WHERE landing_id=?",(lid,))
    c.execute("DELETE FROM inspectors WHERE landing_id=?",(lid,))
    c.execute("DELETE FROM attachments WHERE landing_id=?",(lid,))
    c.execute("DELETE FROM landings WHERE id=?",(lid,))
    c.commit(); c.close()
    return jsonify({"ok":True})

@app.get("/api/backup")
@admin
def backup():
    # SQLite backup to a separate file
    import sqlite3 as _sqlite3
    path=os.path.join(BASE,"backup_database.db")
    srcdb=_sqlite3.connect(DB); dst=_sqlite3.connect(path)
    srcdb.backup(dst); dst.close(); srcdb.close()
    return send_file(path,as_attachment=True,download_name="نسخة_احتياطية_لنظام_الإنزال.db",mimetype="application/octet-stream")

@app.post("/api/landings/<int:lid>/status")
@auth
def landing_status(lid):
    d=request.json or {}; status=d.get("status")
    allowed={"مسودة","مراجعة","معتمد"}
    if status not in allowed: return jsonify({"ok":False,"error":"حالة غير صحيحة"}),400
    c=db()
    if not c.execute("SELECT id FROM landings WHERE id=?",(lid,)).fetchone(): c.close(); return jsonify({"ok":False,"error":"المحضر غير موجود"}),404
    now=datetime.datetime.now().isoformat(timespec="seconds")
    c.execute("INSERT OR REPLACE INTO landing_status(landing_id,status,updated_by,updated_at) VALUES(?,?,?,?)",(lid,status,current()["username"],now))
    c.commit(); c.close(); return jsonify({"ok":True,"status":status})

@app.post("/api/landings/<int:lid>/sign")
@auth
def sign_landing(lid):
    d=request.json or {}; name=(d.get("inspector_name") or "").strip()
    if not name: return jsonify({"ok":False,"error":"اسم المفتش مطلوب"}),400
    c=db()
    if not c.execute("SELECT id FROM landings WHERE id=?",(lid,)).fetchone(): c.close(); return jsonify({"ok":False,"error":"المحضر غير موجود"}),404
    now=datetime.datetime.now().isoformat(timespec="seconds")
    c.execute("INSERT INTO landing_signatures(landing_id,inspector_name,signature_text,signed_at) VALUES(?,?,?,?)",(lid,name,d.get("signature_text","تم الاعتماد إلكترونيًا"),now))
    c.commit(); c.close(); return jsonify({"ok":True})

@app.get("/api/ships")
@auth
def ships():
    c=db(); x=[dict(r) for r in c.execute("SELECT * FROM ships ORDER BY ship_name").fetchall()]; c.close(); return jsonify(x)

@app.post("/api/ships")
@admin
def add_ship():
    d=request.json or {}
    if not d.get("ship_no") or not d.get("ship_name"): return jsonify({"ok":False,"error":"اسم السفينة ورقمها مطلوبان"}),400
    c=db()
    try:
        c.execute("INSERT INTO ships(ship_no,ship_name,owner_name,license_no,notes) VALUES(?,?,?,?,?)",(d["ship_no"],d["ship_name"],d.get("owner_name"),d.get("license_no"),d.get("notes")))
        c.commit()
    except sqlite3.IntegrityError: c.close(); return jsonify({"ok":False,"error":"رقم السفينة موجود مسبقًا"}),400
    c.close(); return jsonify({"ok":True})

@app.get("/api/settings")
@auth
def settings():
    return jsonify({"system_name":"نظام تسجيل إنزال الأسماك في الدقم","entity":"الوسطى – ميناء الصيد البحري","unit":"وحدة التفتيش","version":"8.0"})

@app.get("/api/report")
@auth
def report():
    c=db()
    rows=c.execute("SELECT * FROM landings ORDER BY landing_date DESC, landing_time DESC").fetchall()
    total=sum((r["total_qty"] or 0) for r in rows)
    species={}
    for r in rows:
        for f in c.execute("SELECT fish_name,quantity FROM fish WHERE landing_id=?",(r["id"],)):
            species[f["fish_name"]]=species.get(f["fish_name"],0)+(f["quantity"] or 0)
    c.close()
    return jsonify({"count":len(rows),"total_qty":total,"species":species})

if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000,debug=False)

@app.get('/health')
def health():
    return jsonify({'ok': True})
