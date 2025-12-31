# server.py
from __future__ import annotations
import os, json, sqlite3, datetime, sys
from functools import wraps
from typing import Any, Dict, List
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, send_file, abort, flash, jsonify, make_response
)
from werkzeug.security import generate_password_hash, check_password_hash

# ========================================================
#  SETUP FOR EXE (PyInstaller) & PATH CONFIGURATION
# ========================================================
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# تحديد المجلد الأساسي: ضروري جداً لكي لا تفقد البيانات عند تحويل البرنامج لـ EXE
BASE_DIR = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(__file__)

# إعداد Flask مع المسارات الصحيحة
app = Flask(__name__, 
            static_folder=resource_path("static"), 
            template_folder=resource_path("templates"))

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "prod-secret-key-change-this-immediately-in-production")
# جعل مجلد الرفع بجانب ملف التشغيل
app.config["UPLOAD_FOLDER"] = os.path.join(BASE_DIR, "uploads")
app.config["ALLOWED_EXTENSIONS"] = {'png', 'jpg', 'jpeg', 'pdf', 'doc', 'docx'}

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# =========================
# Security Helpers
# =========================
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = os.urandom(24).hex()
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('csrf_token'):
            abort(403)

# =========================
# Admins DB helpers (SQLite)
# =========================
DB_PATH = os.path.join(BASE_DIR, "admins.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_admins():
    """Create admins table if not exists and seed a default super admin."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS admins (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role     TEXT NOT NULL
        )
        """
    )
    # seed default admin if missing
    cur.execute("SELECT 1 FROM admins WHERE username = ?", ("admin",))
    if cur.fetchone() is None:
        hashed_pw = generate_password_hash("admin123")
        cur.execute("INSERT INTO admins(username, password, role) VALUES(?,?,?)",
                    ("admin", hashed_pw, "super"))
    conn.commit()
    conn.close()

# =========================
# Students DB helpers (SQLite)
# =========================
STUDENTS_DB_PATH = os.path.join(BASE_DIR, "students.db")

def get_students_db():
    conn = sqlite3.connect(STUDENTS_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_students_db():
    """Create students database tables."""
    conn = get_students_db()
    cur = conn.cursor()

    # Students table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            full_name_en TEXT,
            student_id TEXT UNIQUE NOT NULL,
            email TEXT,
            phone TEXT,
            college TEXT,
            department TEXT,
            department_en TEXT,
            level TEXT,
            level_en TEXT,
            study_type TEXT,
            password TEXT,
            image_filename TEXT
        )
    """)
    
    # Auto-migration columns
    columns = ["full_name_en", "department_en", "level_en", "study_type", "password"]
    for col in columns:
        try: cur.execute(f"ALTER TABLE students ADD COLUMN {col} TEXT")
        except sqlite3.OperationalError: pass

    # Admission table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS admission (
            student_id INTEGER PRIMARY KEY,
            type TEXT,
            year TEXT,
            avg TEXT,
            notes TEXT,
            graduation_date TEXT,
            FOREIGN KEY (student_id) REFERENCES students (id)
        )
    """)
    try: cur.execute("ALTER TABLE admission ADD COLUMN graduation_date TEXT")
    except sqlite3.OperationalError: pass

    # Courses table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            course_name TEXT,
            semester TEXT,
            credits INTEGER,
            coursework_total REAL DEFAULT 0,
            coursework_breakdown TEXT DEFAULT '[]',
            final_exam REAL DEFAULT 0,
            grade TEXT DEFAULT '0',
            FOREIGN KEY (student_id) REFERENCES students (id)
        )
    """)
    course_cols = [
        ("coursework_total", "REAL DEFAULT 0"),
        ("coursework_breakdown", "TEXT DEFAULT '[]'"),
        ("final_exam", "REAL DEFAULT 0"),
        ("grade", "TEXT DEFAULT '0'")
    ]
    for col, definition in course_cols:
        try: cur.execute(f"ALTER TABLE courses ADD COLUMN {col} {definition}")
        except sqlite3.OperationalError: pass

    # Research table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS research (
            student_id INTEGER PRIMARY KEY,
            title TEXT,
            supervisor TEXT,
            start_date TEXT,
            keywords TEXT,
            abstract TEXT,
            research_filename TEXT,
            credits INTEGER DEFAULT 0,
            grade TEXT,
            FOREIGN KEY (student_id) REFERENCES students (id)
        )
    """)
    try: cur.execute("ALTER TABLE research ADD COLUMN research_filename TEXT")
    except sqlite3.OperationalError: pass
    try: cur.execute("ALTER TABLE research ADD COLUMN credits INTEGER DEFAULT 0")
    except sqlite3.OperationalError: pass
    try: cur.execute("ALTER TABLE research ADD COLUMN grade TEXT")
    except sqlite3.OperationalError: pass

    # Competency table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS competency (
            student_id INTEGER PRIMARY KEY,
            exam_result TEXT,
            exam_date TEXT,
            english_result TEXT,
            notes TEXT,
            FOREIGN KEY (student_id) REFERENCES students (id)
        )
    """)

    # Plan table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS plan (
            student_id INTEGER PRIMARY KEY,
            committee_name TEXT,
            supervisor TEXT,
            members TEXT,
            discussion_date TEXT,
            notes TEXT,
            FOREIGN KEY (student_id) REFERENCES students (id)
        )
    """)

    conn.commit()
    conn.close()

with app.app_context():
    init_admins()
    init_students_db()

# =========================
# Auth helpers
# =========================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        u = session.get("user")
        if not u or u.get("role") not in {"super", "admin"}:
            abort(403)
        return f(*args, **kwargs)
    return wrapper

def safe_int(v, default=0):
    try: return int(v)
    except Exception: return default

# =========================
# Auth routes
# =========================
@app.route("/")
def home():
    if "user" in session:
        if session["user"]["role"] == "student":
            return redirect(url_for("student_portal"))
        else:
            return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    msg = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()
        
        # 1. Check Admins
        conn = get_db()
        admin_row = conn.execute("SELECT username, password, role FROM admins WHERE username=?", (username,)).fetchone()
        conn.close()
        
        if admin_row and check_password_hash(admin_row["password"], password):
            session["user"] = {"username": admin_row["username"], "role": admin_row["role"]}
            return redirect(url_for("dashboard"))
            
        # 2. Check Students
        conn_s = get_students_db()
        student_row = conn_s.execute("SELECT id, full_name, student_id, password FROM students WHERE student_id=?", (username,)).fetchone()
        conn_s.close()

        valid_student = False
        if student_row:
            db_pass = student_row["password"]
            if db_pass and len(db_pass) > 20: 
                if check_password_hash(db_pass, password):
                    valid_student = True
            elif password == student_row["student_id"]:
                valid_student = True

        if valid_student:
            session["user"] = {
                "username": student_row["full_name"], 
                "role": "student", 
                "db_id": student_row["id"]
            }
            flash(f"أهلاً بك {student_row['full_name']}", "success")
            return redirect(url_for("student_portal"))

        msg = "بيانات الدخول غير صحيحة"
        flash(msg, "error")

    return render_template("login.html", message=msg)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# =========================
# Student Portal Routes (Bologna System 50/50)
# =========================
@app.route("/my_portal")
@login_required
def student_portal():
    # حماية: التأكد أن المستخدم طالب
    if session["user"].get("role") != "student":
        return redirect(url_for("dashboard"))

    student_db_id = session["user"]["db_id"]
    conn = get_students_db()
    
    # جلب معلومات الطالب
    student_info = conn.execute("SELECT full_name, student_id, college, department FROM students WHERE id=?", (student_db_id,)).fetchone()
    
    # جلب المواد
    raw_courses = conn.execute("SELECT course_name, semester, credits, coursework_total, final_exam, grade, coursework_breakdown FROM courses WHERE student_id=?", (student_db_id,)).fetchall()
    conn.close()
    
    # معالجة البيانات: تحويل النص المخزن (JSON) إلى قائمة أرقام
    courses = []
    for c in raw_courses:
        course_dict = dict(c) 
        
        # فك تشفير تفاصيل السعي
        try:
            breakdown = json.loads(c["coursework_breakdown"] or "[]")
            clean_breakdown = []
            for mark in breakdown:
                try:
                    val = float(mark)
                    if val.is_integer():
                        clean_breakdown.append(int(val))
                    else:
                        clean_breakdown.append(val)
                except:
                    clean_breakdown.append(0)
            
            course_dict["coursework_breakdown"] = clean_breakdown
            
        except:
            course_dict["coursework_breakdown"] = []
            
        courses.append(course_dict)
    
    return render_template("student_portal.html", student=student_info, courses=courses)

@app.route("/student/change_password", methods=["POST"])
@login_required
def student_change_password():
    if session["user"].get("role") != "student":
        return redirect(url_for("login"))
        
    old_pass = request.form.get("old_password", "").strip()
    new_pass = request.form.get("new_password", "").strip()
    
    if not new_pass or len(new_pass) < 6:
        flash("كلمة المرور الجديدة يجب أن تكون 6 أحرف على الأقل", "error")
        return redirect(url_for("student_portal"))

    student_db_id = session["user"]["db_id"]
    conn = get_students_db()
    row = conn.execute("SELECT student_id, password FROM students WHERE id=?", (student_db_id,)).fetchone()
    
    if not row:
        conn.close()
        return redirect(url_for("logout"))
        
    current_db_pass = row["password"]
    student_uni_id = row["student_id"]
    
    is_old_valid = False
    if current_db_pass and len(current_db_pass) > 20:
        if check_password_hash(current_db_pass, old_pass):
            is_old_valid = True
    elif old_pass == student_uni_id:
        is_old_valid = True
        
    if not is_old_valid:
        flash("كلمة المرور الحالية غير صحيحة", "error")
        conn.close()
        return redirect(url_for("student_portal"))
        
    new_hashed = generate_password_hash(new_pass)
    conn.execute("UPDATE students SET password = ? WHERE id = ?", (new_hashed, student_db_id))
    conn.commit()
    conn.close()
    
    flash("تم تغيير كلمة المرور بنجاح", "success")
    return redirect(url_for("student_portal"))

# =========================
# Dashboard + manage admins
# =========================
@app.route("/dashboard")
@login_required
@admin_only
def dashboard():
    conn = get_students_db()
    cur = conn.cursor()
    total_students = cur.execute("SELECT COUNT(*) FROM students").fetchone()[0]
    master_count = cur.execute("SELECT COUNT(*) FROM students WHERE level LIKE '%ماجستير%'").fetchone()[0]
    phd_count = cur.execute("SELECT COUNT(*) FROM students WHERE level LIKE '%دكتوراه%'").fetchone()[0]
    morning_count = cur.execute("SELECT COUNT(*) FROM students WHERE study_type = 'صباحي'").fetchone()[0]
    evening_count = cur.execute("SELECT COUNT(*) FROM students WHERE study_type = 'مسائي'").fetchone()[0]
    conn.close()
    
    stats = {
        "total": total_students, "master": master_count, "phd": phd_count,
        "morning": morning_count, "evening": evening_count
    }
    return render_template("dashboard.html", user=session.get("user"), stats=stats)

@app.route("/admins", methods=["GET", "POST"])
@login_required
@admin_only
def admins():
    conn = get_db()
    cur = conn.cursor()

    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            username = (request.form.get("new_username") or "").strip()
            password = (request.form.get("new_password") or "").strip()
            role = (request.form.get("new_role") or "admin").strip()
            if username and password:
                try:
                    hashed_pw = generate_password_hash(password)
                    cur.execute("INSERT INTO admins(username,password,role) VALUES(?,?,?)",
                                 (username, hashed_pw, role))
                    conn.commit()
                    flash("تمت إضافة المشرف", "success")
                except sqlite3.IntegrityError:
                    flash("المستخدم موجود مسبقًا", "error")
        elif action == "delete":
            username = (request.form.get("username") or "").strip()
            if username != "admin" and username != session['user']['username']:
                cur.execute("DELETE FROM admins WHERE username = ?", (username,))
                conn.commit()
                flash(f"تم حذف المشرف {username}", "success")
            else:
                flash("لا يمكن حذف هذا الحساب", "error")

    admins_list = cur.execute("SELECT username, role FROM admins ORDER BY username").fetchall()
    conn.close()
    return render_template("admins.html", admins=admins_list)

# =========================
# Student application steps
# =========================
@app.route("/info", methods=["GET", "POST"])
@login_required
def info():
    if session["user"].get("role") == "student": return redirect(url_for("student_portal"))

    if request.method == "POST":
        full_name = (request.form.get("full_name") or "").strip()
        student_id_input = (request.form.get("student_id") or "").strip()
        full_name_en = (request.form.get("full_name_en") or "").strip()
        level_en = (request.form.get("level_en") or "").strip()
        department_en = (request.form.get("department_en") or "").strip()
        
        if not full_name or not student_id_input:
            flash("الرجاء إدخال جميع البيانات المطلوبة", "error")
            return redirect(url_for("info"))

        f = request.files.get("student_image")
        filename_to_store = ""
        if f and f.filename:
            if not allowed_file(f.filename):
                flash("صيغة الملف غير مدعومة", "error")
                return redirect(url_for("info"))
            filename_to_store = f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{f.filename}"

        try:
            conn = get_students_db()
            cur = conn.cursor()
            student_db_id = session.get("student_id")
            
            if student_db_id:
                cur.execute("""
                    UPDATE students 
                    SET full_name=?, full_name_en=?, student_id=?, email=?, phone=?, college=?, 
                        department=?, department_en=?, level=?, level_en=?, study_type=?, 
                        image_filename=COALESCE(?, image_filename)
                    WHERE id=?
                """, (full_name, full_name_en, student_id_input, request.form.get("email"), request.form.get("phone"),
                      request.form.get("college"), request.form.get("department"), department_en,
                      request.form.get("level"), level_en, request.form.get("study_type"),
                      filename_to_store if filename_to_store else None, student_db_id))
            else:
                cur.execute("""
                    INSERT INTO students (full_name, full_name_en, student_id, email, phone, college, department, department_en, level, level_en, study_type, image_filename)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (full_name, full_name_en, student_id_input, request.form.get("email"), request.form.get("phone"),
                      request.form.get("college"), request.form.get("department"), department_en,
                      request.form.get("level"), level_en, request.form.get("study_type"), filename_to_store))
                student_db_id = cur.lastrowid
            
            if filename_to_store and f:
                f.save(os.path.join(app.config["UPLOAD_FOLDER"], filename_to_store))

            conn.commit()
            conn.close()
            session["student_id"] = student_db_id
            flash("تم حفظ معلومات الطالب بنجاح", "success")
            return redirect(url_for("admission"))
        except sqlite3.IntegrityError:
            conn.close()
            flash(f"الرقم الجامعي مسجل مسبقاً.", "error")
            return redirect(url_for("info"))

    student_id = session.get("student_id")
    data = {}
    if student_id:
        conn = get_students_db()
        row = conn.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
        conn.close()
        if row: data = dict(row)
    return render_template("info.html", data=data)

@app.route("/admission", methods=["GET", "POST"])
@login_required
def admission():
    if session["user"].get("role") == "student": return redirect(url_for("student_portal"))

    student_id = session.get("student_id")
    if not student_id: return redirect(url_for("info"))

    conn = get_students_db()
    if request.method == "POST":
        conn.execute("INSERT OR REPLACE INTO admission (student_id, type, year, avg, notes, graduation_date) VALUES (?, ?, ?, ?, ?, ?)",
                     (student_id, request.form.get("type"), request.form.get("year"), request.form.get("avg"), request.form.get("notes"), request.form.get("graduation_date")))
        conn.commit()
        conn.close()
        return redirect(url_for("courses"))

    row = conn.execute("SELECT * FROM admission WHERE student_id = ?", (student_id,)).fetchone()
    conn.close()
    return render_template("admission.html", data=dict(row) if row else {})

@app.route("/courses", methods=["GET", "POST"])
@login_required
def courses():
    if session["user"].get("role") == "student": return redirect(url_for("student_portal"))

    student_id = session.get("student_id")
    if not student_id: return redirect(url_for("info"))
    conn = get_students_db()
    
    if request.method == "POST":
        if request.form.get("action") == "delete":
            cid = safe_int(request.form.get("course_id", -1))
            if cid > 0:
                conn.execute("DELETE FROM courses WHERE id = ? AND student_id = ?", (cid, student_id))
                conn.commit()
                flash("تم حذف المادة", "success")
            conn.close()
            return redirect(url_for("courses"))
            
        names = request.form.getlist("course_name[]")
        semesters = request.form.getlist("course_term[]")
        credits_list = request.form.getlist("course_units[]")
        if names:
            for i in range(len(names)):
                c_name = names[i].strip()
                c_sem = semesters[i].strip() if i < len(semesters) else ""
                c_cred = safe_int(credits_list[i], 0) if i < len(credits_list) else 0
                if c_name:
                    conn.execute("INSERT INTO courses (student_id, course_name, semester, credits) VALUES (?, ?, ?, ?)", (student_id, c_name, c_sem, c_cred))
            conn.commit()
        conn.close()
        return redirect(url_for("research"))

    courses_list = conn.execute("SELECT * FROM courses WHERE student_id = ?", (student_id,)).fetchall()
    processed = []
    for c in courses_list:
        d = dict(c)
        try: d['coursework_breakdown'] = json.loads(c['coursework_breakdown'] or '[]')
        except: d['coursework_breakdown'] = []
        processed.append(d)
    conn.close()
    total_credits = sum(safe_int(c["credits"], 0) for c in processed)
    return render_template("courses.html", data={}, courses=processed, total_credits=total_credits)

@app.route("/research", methods=["GET", "POST"])
@login_required
def research():
    if session["user"].get("role") == "student": return redirect(url_for("student_portal"))

    student_id = session.get("student_id")
    if not student_id: return redirect(url_for("info"))
    conn = get_students_db()
    
    if request.method == "POST":
        keywords = ", ".join([k.strip() for k in request.form.getlist("new_keyword[]") if k.strip()])
        f = request.files.get("research_file")
        fname = None
        if f and f.filename and allowed_file(f.filename):
            fname = f"research_{student_id}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{f.filename}"
            f.save(os.path.join(app.config["UPLOAD_FOLDER"], fname))
        
        conn.execute("""
            INSERT OR REPLACE INTO research (student_id, title, supervisor, start_date, keywords, abstract, research_filename, credits, grade)
            VALUES (?, ?, ?, ?, ?, ?, COALESCE(?, (SELECT research_filename FROM research WHERE student_id = ?)), ?, ?)
        """, (student_id, request.form.get("title"), request.form.get("supervisor"), request.form.get("start_date"), keywords,
              request.form.get("abstract"), fname, student_id, request.form.get("credits", 0), request.form.get("grade")))
        conn.commit()
        conn.close()
        return redirect(url_for("competency"))

    row = conn.execute("SELECT * FROM research WHERE student_id = ?", (student_id,)).fetchone()
    conn.close()
    return render_template("research.html", data=dict(row) if row else {})

@app.route("/competency", methods=["GET", "POST"])
@login_required
def competency():
    if session["user"].get("role") == "student": return redirect(url_for("student_portal"))

    student_id = session.get("student_id")
    if not student_id: return redirect(url_for("info"))
    conn = get_students_db()
    if request.method == "POST":
        conn.execute("INSERT OR REPLACE INTO competency (student_id, exam_result, exam_date, english_result, notes) VALUES (?, ?, ?, ?, ?)",
                     (student_id, request.form.get("comp_exam"), request.form.get("comp_date"), request.form.get("achievements"), request.form.get("notes")))
        conn.commit()
        conn.close()
        return redirect(url_for("plan"))
    
    row = conn.execute("SELECT * FROM competency WHERE student_id = ?", (student_id,)).fetchone()
    conn.close()
    data = {}
    if row:
        data = {'comp_exam': row['exam_result'], 'comp_date': row['exam_date'], 'achievements': row['english_result'], 'notes': row['notes']}
    return render_template("competency.html", data=data)

@app.route("/plan", methods=["GET", "POST"])
@login_required
def plan():
    if session["user"].get("role") == "student": return redirect(url_for("student_portal"))

    student_id = session.get("student_id")
    if not student_id: return redirect(url_for("info"))
    conn = get_students_db()
    
    if request.method == "POST":
        action = request.form.get("action")
        current_plan = conn.execute("SELECT members FROM plan WHERE student_id = ?", (student_id,)).fetchone()
        existing_mems = current_plan["members"] if current_plan and current_plan["members"] else ""
        
        if action == "delete_member":
            mem = request.form.get("member_to_delete", "").strip()
            m_list = [m.strip() for m in existing_mems.split(',') if m.strip()]
            if mem in m_list: m_list.remove(mem)
            conn.execute("INSERT OR REPLACE INTO plan (student_id, members) VALUES (?, ?)", (student_id, ", ".join(m_list)))
            conn.commit()
            conn.close()
            return redirect(url_for("plan"))
            
        new_mems = [m.strip() for m in request.form.getlist("new_member[]") if m.strip()]
        final_list = [m.strip() for m in existing_mems.split(',') if m.strip()]
        for nm in new_mems:
            if nm not in final_list: final_list.append(nm)
            
        conn.execute("INSERT OR REPLACE INTO plan (student_id, committee_name, supervisor, members, discussion_date, notes) VALUES (?, ?, ?, ?, ?, ?)",
                     (student_id, request.form.get("committee_name"), request.form.get("supervisor"), ", ".join(final_list), request.form.get("discussion_date"), request.form.get("notes")))
        conn.commit()
        conn.close()
        return redirect(url_for("review"))

    row = conn.execute("SELECT * FROM plan WHERE student_id = ?", (student_id,)).fetchone()
    conn.close()
    return render_template("plan.html", data=dict(row) if row else {})

@app.route("/review")
@login_required
def review():
    student_id = session.get("student_id")
    if not student_id: return redirect(url_for("info"))
    conn = get_students_db()
    s = conn.execute("SELECT * FROM students WHERE id=?", (student_id,)).fetchone()
    a = conn.execute("SELECT * FROM admission WHERE student_id=?", (student_id,)).fetchone()
    c = conn.execute("SELECT * FROM courses WHERE student_id=?", (student_id,)).fetchall()
    r = conn.execute("SELECT * FROM research WHERE student_id=?", (student_id,)).fetchone()
    comp = conn.execute("SELECT * FROM competency WHERE student_id=?", (student_id,)).fetchone()
    p = conn.execute("SELECT * FROM plan WHERE student_id=?", (student_id,)).fetchone()
    conn.close()
    return render_template("review.html", student=s, admission=a, courses=c, research=r, competency=comp, plan=p)

# =========================
# Admin Management Routes
# =========================
@app.route("/admin/students")
@login_required
@admin_only
def admin_students_list():
    conn = get_students_db()
    q = request.args.get("q", "").strip()
    level = request.args.get("level", "").strip()
    study = request.args.get("study_type", "").strip()
    
    sql = "SELECT s.id, s.full_name, s.student_id, s.study_type, s.level, a.avg, a.type as admission_type FROM students s LEFT JOIN admission a ON s.id = a.student_id WHERE 1=1"
    params = []
    if q:
        sql += " AND (s.full_name LIKE ? OR s.student_id LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%"])
    if level:
        sql += " AND s.level = ?"
        params.append(level)
    if study:
        sql += " AND s.study_type = ?"
        params.append(study)
    sql += " ORDER BY s.id DESC"
    
    students = conn.execute(sql, params).fetchall()
    conn.close()
    return render_template("admin_students_list.html", students=students)

@app.route("/admin/student/<int:student_id>/full_edit")
@login_required
@admin_only
def admin_student_full_edit(student_id):
    session["student_id"] = student_id
    flash(f"تم فتح سجل الطالب ID:{student_id} للتعديل.", "info")
    return redirect(url_for("info"))

@app.route("/admin/student/<int:student_id>/view")
@login_required
@admin_only
def admin_student_view(student_id):
    conn = get_students_db()
    s = conn.execute("SELECT * FROM students WHERE id=?", (student_id,)).fetchone()
    a = conn.execute("SELECT * FROM admission WHERE student_id=?", (student_id,)).fetchone()
    c = conn.execute("SELECT * FROM courses WHERE student_id=?", (student_id,)).fetchall()
    r = conn.execute("SELECT * FROM research WHERE student_id=?", (student_id,)).fetchone()
    comp = conn.execute("SELECT * FROM competency WHERE student_id=?", (student_id,)).fetchone()
    p = conn.execute("SELECT * FROM plan WHERE student_id=?", (student_id,)).fetchone()
    conn.close()
    return render_template("review.html", student=s, admission=a, courses=c, research=r, competency=comp, plan=p, is_admin_view=True)

@app.route("/admin/student/<int:student_id>/edit", methods=["GET", "POST"])
@login_required
@admin_only
def admin_student_edit(student_id):
    conn = get_students_db()
    if request.method == "POST":
        total_g = 0
        count_c = 0
        existing_courses = conn.execute("SELECT id FROM courses WHERE student_id=?", (student_id,)).fetchall()
        for course in existing_courses:
            cid = course["id"]
            
            # حساب مجموع السعي (يجمع تلقائياً القيم المدخلة سواء كانت 5 أو 10)
            cw_tot = 0
            breakdown = []
            for i in range(1, 6):
                val = safe_int(request.form.get(f"cw{i}_{cid}", 0)) # يأخذ القيمة مهما كانت
                cw_tot += val
                breakdown.append(val)
            
            final = safe_int(request.form.get(f"final_{cid}", 0))
            grade = cw_tot + final
            
            conn.execute("UPDATE courses SET coursework_total=?, coursework_breakdown=?, final_exam=?, grade=? WHERE id=?",
                         (cw_tot, json.dumps(breakdown), final, grade, cid))
            total_g += grade
            count_c += 1
        
        avg = round(total_g / count_c, 2) if count_c > 0 else 0
        conn.execute("INSERT OR REPLACE INTO admission (student_id, type, year, avg, notes) VALUES (?, ?, ?, ?, ?)",
                     (student_id, request.form.get("type"), request.form.get("year"), str(avg), request.form.get("notes")))
        conn.commit()
        flash("تم تحديث الدرجات", "success")
        conn.close()
        return redirect(url_for("admin_students_list"))

    s = conn.execute("SELECT * FROM students WHERE id=?", (student_id,)).fetchone()
    a = conn.execute("SELECT * FROM admission WHERE student_id=?", (student_id,)).fetchone()
    c = conn.execute("SELECT * FROM courses WHERE student_id=?", (student_id,)).fetchall()
    
    proc_courses = []
    for co in c:
        d = dict(co)
        try: d['coursework_breakdown'] = json.loads(co['coursework_breakdown'] or '[0,0,0,0,0]')
        except: d['coursework_breakdown'] = [0]*5
        proc_courses.append(d)
        
    conn.close()
    return render_template("admin_student_edit.html", student=s, admission=a, courses=proc_courses)

@app.route("/admin/student/<int:student_id>/delete", methods=["POST"])
@login_required
@admin_only
def admin_student_delete(student_id):
    conn = get_students_db()
    s = conn.execute("SELECT image_filename FROM students WHERE id=?", (student_id,)).fetchone()
    if s and s["image_filename"]:
        try: os.remove(os.path.join(app.config["UPLOAD_FOLDER"], s["image_filename"]))
        except: pass
    
    r = conn.execute("SELECT research_filename FROM research WHERE student_id=?", (student_id,)).fetchone()
    if r and r["research_filename"]:
        try: os.remove(os.path.join(app.config["UPLOAD_FOLDER"], r["research_filename"]))
        except: pass

    for t in ["students", "admission", "courses", "research", "competency", "plan"]:
        col = "id" if t == "students" else "student_id"
        conn.execute(f"DELETE FROM {t} WHERE {col}=?", (student_id,))
    
    conn.commit()
    conn.close()
    flash("تم حذف الطالب", "success")
    return redirect(url_for("admin_students_list"))

@app.route("/admin/export/csv")
@login_required
@admin_only
def admin_export_csv():
    conn = get_students_db()
    students = conn.execute("SELECT s.id, s.full_name, s.student_id, s.level, s.study_type, s.department, s.college, a.avg, a.type FROM students s LEFT JOIN admission a ON s.id=a.student_id ORDER BY s.id DESC").fetchall()
    conn.close()
    out = "\ufeffID,الاسم,الرقم الجامعي,المرحلة,الدراسة,القسم,الكلية,المعدل,القبول\n"
    for s in students:
        row = [str(s[k] or "") for k in s.keys()]
        out += ",".join([f'"{r}"' if "," in r else r for r in row]) + "\n"
    resp = make_response(out)
    resp.headers["Content-Disposition"] = "attachment; filename=students.csv"
    resp.headers["Content-type"] = "text/csv; charset=utf-8"
    return resp

@app.route("/admin/student/<int:student_id>/print_application")
@login_required
def admin_student_print(student_id):
    conn = get_students_db()
    s = conn.execute("SELECT * FROM students WHERE id=?", (student_id,)).fetchone()
    a = conn.execute("SELECT * FROM admission WHERE student_id=?", (student_id,)).fetchone()
    c = conn.execute("SELECT * FROM courses WHERE student_id=?", (student_id,)).fetchall()
    r = conn.execute("SELECT * FROM research WHERE student_id=?", (student_id,)).fetchone()
    comp = conn.execute("SELECT * FROM competency WHERE student_id=?", (student_id,)).fetchone()
    p = conn.execute("SELECT * FROM plan WHERE student_id=?", (student_id,)).fetchone()
    conn.close()
    
    sum1, cnt1, sum2, cnt2, creds = 0,0,0,0,0
    for co in c:
        try:
            gr = float(co["grade"])
            creds += int(co["credits"])
            if 'أول' in co["semester"]: sum1, cnt1 = sum1+gr, cnt1+1
            elif 'ثاني' in co["semester"]: sum2, cnt2 = sum2+gr, cnt2+1
        except: pass
    
    return render_template("print_student.html", student=s, admission=a, courses=c, research=r, competency=comp, plan=p,
                           avg_sem1=round(sum1/cnt1,2) if cnt1 else '---',
                           avg_sem2=round(sum2/cnt2,2) if cnt2 else '---',
                           course_credits_sum=creds,
                           total_credits_all=creds + (int(r['credits']) if r and r['credits'] else 0),
                           thesis_grade=r['grade'] if r and r['grade'] else '.......',
                           grad_date=a['graduation_date'] if a and a['graduation_date'] else '../../....',
                           issue_date=datetime.datetime.now(),
                           transcript_number=s['student_id'] or str(s['id']).zfill(5))

@app.route("/admin/research_registry")
@login_required
@admin_only
def research_registry():
    q = request.args.get("q", "").strip()
    ftype = request.args.get("filter_type", "title")
    sql = "SELECT s.full_name, s.student_id as uid, r.title, r.supervisor, r.start_date, r.research_filename FROM research r JOIN students s ON r.student_id = s.id WHERE 1=1"
    params = []
    if q:
        if ftype == "student_name": sql += " AND s.full_name LIKE ?"
        elif ftype == "supervisor": sql += " AND r.supervisor LIKE ?"
        elif ftype == "title": sql += " AND r.title LIKE ?"
        elif ftype == "date": sql += " AND r.start_date LIKE ?"
        elif ftype == "id": sql += " AND s.student_id LIKE ?"
        else: sql += " AND (r.title LIKE ? OR s.full_name LIKE ?)"; params.append(f"%{q}%")
        params.append(f"%{q}%")
    
    conn = get_students_db()
    res = conn.execute(sql, params).fetchall()
    conn.close()
    return render_template("research_registry.html", researches=res, filter_type=ftype)

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_file(os.path.join(app.config["UPLOAD_FOLDER"], filename))

@app.errorhandler(403)
def forbidden(e): return render_template("403.html"), 403
@app.errorhandler(404)
def page_not_found(e): return render_template("404.html"), 404
@app.route("/_health")
def health(): return {"ok": True}

if __name__ == "__main__":
    app.run(debug=True)