import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore
import hashlib
import datetime
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pandas as pd  # Assuming available; if not, add to requirements.txt
from html import escape  # Built-in, for sanitization

# --- 1. CONFIGURATION & CONSTANTS ---
st.set_page_config(page_title="AMC Exam Portal Pro", layout="wide", page_icon="🎓")

# Academic Constants (unchanged)
BLOOMS_LEVELS = ["L1", "L2", "L3", "L4", "L5", "L6"]
COS_LIST = ["CO1", "CO2", "CO3", "CO4", "CO5", "CO6"]
EXAM_TYPES = ["IA1", "IA2", "IA3", "SEE", "Makeup", "Other"]
DEPTS = ["CSE", "ECE", "MECH", "ISE", "CIVIL", "EEE", "MBA", "MCA", "Basic Science"]
SEMESTERS = ["1st", "2nd", "3rd", "4th", "5th", "6th", "7th", "8th"]

# --- [UNIFIED FULL-PAGE THEME] (IMPROVED: Added mobile CSS) ---
def load_custom_css():
    theme_color = "#fff7ed"  # Light Orange
    st.markdown(f"""
    <style>
        .stApp {{ background-color: {theme_color}; font-family: 'Inter', sans-serif; color: #000000 !important; }}
        section[data-testid="stSidebar"] {{ background-color: {theme_color}; border-right: 1px solid rgba(0,0,0,0.05); }}
        section[data-testid="stSidebar"] * {{ color: #1e293b !important; }}
        h1, h2, h3 {{ color: #1e293b !important; font-weight: 800 !important; }}
        div[data-testid="stExpander"], div[data-testid="stForm"] {{ background: #ffffff; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); border: 1px solid #cbd5e1; padding: 20px; margin-bottom: 1rem; }}
        input, textarea, select {{ background-color: #ffffff !important; color: #000000 !important; border: 1px solid #cbd5e1; font-weight: 600 !important; }}
        button[kind="primary"] {{ background-color: #2563eb !important; color: white !important; border: none; }}
        .badge {{ padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 12px; }}
        .badge-draft {{ background: #e2e8f0; color: #334155; }}
        .badge-submitted {{ background: #dbeafe; color: #1e40af; }}
        .badge-scrutinized {{ background: #ffedd5; color: #9a3412; }}
        .badge-approved {{ background: #dcfce7; color: #166534; }}
        .badge-revision {{ background: #fee2e2; color: #991b1b; }}
        /* Mobile Responsiveness */
        @media (max-width: 768px) {{ 
            .stApp > div > div {{ flex-direction: column !important; }} 
            input, select {{ width: 100% !important; }} 
        }}
    </style>
    """, unsafe_allow_html=True)

load_custom_css()

# --- 2. FIREBASE SETUP (IMPROVED: Cached) ---
db = None

@st.cache_resource
def init_firebase():
    global db
    if not firebase_admin._apps:
        try:
            if "firestore" in st.secrets:
                key_dict = dict(st.secrets["firestore"])
                cred = credentials.Certificate(key_dict)
                firebase_admin.initialize_app(cred)
                db = firestore.client()
                return True
            else:
                st.error("⚠️ secrets.toml not found or missing [firestore] section.")
                return False
        except Exception as e:
            st.error(f"🔥 Firebase Initialization Error: {e}")
            return False
    else:
        db = firestore.client()
        return True

firebase_ready = init_firebase()

# --- 3. SECURITY HELPER FUNCTIONS (Reverted to SHA-256; Added Sanitization) ---
def hash_password(password):
    return hashlib.sha256(str.encode(password)).hexdigest()

def login_user(username, password):
    if not db:
        return None
    try:
        doc = db.collection("users").document(username).get()
        if doc.exists:
            u = doc.to_dict()
            if u.get('password') == hash_password(password):
                return u
    except Exception as e:
        st.error(f"Login DB Error: {e}")
    return None

def check_submission_window():
    if not db:
        return True
    try:
        s = db.collection("config").document("settings").get()
        return s.to_dict().get('submission_window_open', True) if s.exists else True
    except Exception as e:
        st.error(f"Config fetch error: {e}")
        return True

# Input sanitization (NEW: Prevents XSS)
def sanitize_input(text: str) -> str:
    return escape(str(text))

# --- 4. HTML GENERATOR (IMPROVED: Sanitized Inputs) ---
def generate_html(details, sections):
    # Sanitize all user inputs
    details = {k: sanitize_input(v) for k, v in details.items()}
    for sec in sections:
        if 'text' in sec:
            sec['text'] = sanitize_input(sec['text'])
        for q in sec.get('questions', []):
            q['text'] = sanitize_input(q['text'])
    
    # Rest of generation logic unchanged (for brevity)
    header_title = f"{details.get('examType', 'Exam')} - {details.get('semester', '')} Semester"
    usn_boxes = "".join(['<div class="box"></div>' for _ in range(10)])
    rows = ""
    for sec in sections:
        if sec.get('isNote'):
            rows += f"<tr><td colspan='5' style='background:#f9f9f9; font-weight:bold; font-style:italic; padding:8px;'>{sec['text']}</td></tr>"
        else:
            for q in sec['questions']:
                if q['text'].strip().upper() == 'OR':
                    rows += "<tr><td colspan='5' style='text-align:center; font-weight:bold; background:#eee;'>OR</td></tr>"
                else:
                    txt = q['text'].replace('\n', '<br>')
                    rows += f"""
                    <tr>
                        <td style='text-align:center; vertical-align:top;'><b>{q['qNo']}</b></td>
                        <td style='vertical-align:top;'>{txt}</td>
                        <td style='text-align:center; vertical-align:top;'>{int(q['marks']) if q['marks'] > 0 else ''}</td>
                        <td style='text-align:center; vertical-align:top;'>{q['co']}</td>
                        <td style='text-align:center; vertical-align:top;'>{q['level']}</td>
                    </tr>"""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8">
    <script>
    window.MathJax = {{ tex: {{ inlineMath: [['$', '$'], ['\\\\(', '\\\\)']] }}, svg: {{ fontCache: 'global' }} }};
    </script>
    <script id="MathJax-script" async src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js"></script>
    <style>
        body {{ font-family: 'Times New Roman', serif; padding: 40px; color: #000; }}
        .paper {{ width: 210mm; margin: 0 auto; background: white; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }}
        td, th {{ border: 1px solid black; padding: 6px; }}
        .header {{ text-align: center; margin-bottom: 20px; border-bottom: 2px solid black; padding-bottom: 10px; }}
        .inst {{ font-size: 24px; font-weight: bold; text-transform: uppercase; font-family: Arial, sans-serif; }}
        .meta {{ display: flex; justify-content: space-between; font-size: 14px; margin: 5px 0; }}
        .box {{ width: 25px; height: 25px; border: 1px solid black; display: inline-block; margin-right: -1px; }}
        .sig-block {{ display: flex; justify-content: space-between; margin-top: 50px; text-align: center; font-size: 12px; }}
        .sig-line {{ border-top: 1px solid black; width: 150px; padding-top: 5px; font-weight: bold; }}
        @media print {{ body {{ padding: 0; }} .paper {{ box-shadow: none; margin: 0; width: 100%; }} }}
    </style>
    </head>
    <body>
        <div class="paper">
            <div class="header">
                <div class="inst">{details.get('instituteName')}</div>
                <div style="font-size:12px; font-weight:bold;">{details.get('subHeader')}</div>
                <div style="font-size:12px; font-weight:bold;">{details.get('department')}</div>
                <div style="font-size:10px; font-style:italic;">{details.get('accreditation')}</div>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;">
                <span style="font-weight:bold; font-size:16px;">USN</span>
                <div style="display:flex;">{usn_boxes}</div>
            </div>
            <div style="text-align:center; font-weight:bold; font-size:16px; text-decoration:underline; margin-bottom:10px;">
                {header_title} - {details.get('acadYear', '')}
            </div>
            <div class="meta">
                <span><b>Course:</b> {details.get('courseName')}</span>
                <span><b>Code:</b> {details.get('courseCode')}</span>
            </div>
            <div class="meta">
                <span><b>Date:</b> {details.get('examDate')}</span>
                <span><b>Duration:</b> {details.get('duration')}</span>
                <span><b>Max Marks:</b> {details.get('maxMarks')}</span>
            </div>
            <table>
                <thead>
                    <tr style="background:#f0f0f0;">
                        <th width="8%">Q.No</th>
                        <th width="62%">Question</th>
                        <th width="10%">Marks</th>
                        <th width="10%">CO</th>
                        <th width="10%">Level</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
            <div class="sig-block">
                <div><div class="sig-line">{details.get('preparedBy','')}<br>Prepared By</div></div>
                <div><div class="sig-line">{details.get('scrutinizedBy','')}<br>Scrutinized By</div></div>
                <div><div class="sig-line">{details.get('approvedBy','')}<br>Approved By</div></div>
            </div>
        </div>
    </body>
    </html>
    """

# --- 5. STATE MANAGEMENT (IMPROVED: Simple Validation Helpers) ---
if 'user' not in st.session_state: st.session_state.user = None

def init_exam_data():
    return {
        'instituteName': 'AMC ENGINEERING COLLEGE', 'subHeader': '(AUTONOMOUS)',
        'accreditation': 'NAAC A+ | NBA Accredited', 'department': 'CSE',
        'acadYear': '2024-2025', 'semester': '5th', 'examType': 'IA1', 'examDate': str(datetime.date.today()),
        'courseName': '', 'courseCode': '', 'maxMarks': 50, 'duration': '90 Mins',
        'preparedBy': '', 'scrutinizedBy': '', 'approvedBy': ''
    }

if 'exam_details' not in st.session_state:
    st.session_state.exam_details = init_exam_data()
if 'sections' not in st.session_state:
    st.session_state.sections = [{'id': 1, 'isNote': False, 'questions': [{'id': 101, 'qNo': '1.a', 'text': '', 'marks': 0, 'co': 'CO1', 'level': 'L1'}]}]
if 'current_doc_id' not in st.session_state: st.session_state.current_doc_id = None
if 'current_doc_status' not in st.session_state: st.session_state.current_doc_status = "NEW"

# Simple validation helper (NEW: Basic checks without Pydantic)
def validate_exam_details(details):
    errors = []
    if details.get('department') not in DEPTS:
        errors.append("Invalid department")
    if details.get('semester') not in SEMESTERS:
        errors.append("Invalid semester")
    if details.get('examType') not in EXAM_TYPES:
        errors.append("Invalid exam type")
    if details.get('courseCode') == '':
        errors.append("Course code required")
    return errors

# --- 6. PRO LOGIN SCREEN (Unchanged) ---
if not st.session_state.user:
    lc1, lc2, lc3 = st.columns([1, 1.5, 1])
    with lc2:
        st.markdown("""
        <div class="login-container">
            <h1 style='margin-bottom:0;'>🎓 AMC Exam Portal</h1>
            <p style='color:gray; font-size:14px;'>Secure Digital Examination System</p>
            <hr style='margin: 20px 0;'>
        </div>
        """, unsafe_allow_html=True)
       
        u = st.text_input("Username", placeholder="e.g. FAC001")
        p = st.text_input("Password", type="password", placeholder="••••••••")
       
        if not firebase_ready:
            st.warning("DB Not Connected. Please setup secrets.toml")
       
        b1, b2, b3 = st.columns([1, 5, 1])
        with b2:
            if st.button("🔒 Secure Login", type="primary", use_container_width=True, disabled=not firebase_ready):
                user = login_user(u, p)
                if user:
                    st.session_state.user = user
                    st.session_state.user['id'] = u
                    st.rerun()
                else:
                    st.error("Invalid Credentials or User does not exist.")
       
        with st.expander("Setup / Debug Info"):
            st.write("First time? You need to manually create an admin user in Firestore 'users' collection.")
            st.code("ID: admin\nRole: admin\nPassword: (Use hash_password function locally to generate)")
    st.stop()

# --- 7. SIDEBAR & LOGOUT (IMPROVED: Error Handling) ---
with st.sidebar:
    role = st.session_state.user.get('role', 'User').lower()
   
    st.markdown(f"""
    <div style='text-align: center; padding: 10px; background: rgba(255,255,255,0.1); border-radius: 10px; margin-bottom: 20px;'>
        <div style='font-size: 40px;'>👤</div>
        <div style='color: white; font-weight: bold; margin-top: 5px;'>{st.session_state.user.get('name')}</div>
        <div style='color: #94a3b8; font-size: 12px; text-transform: uppercase;'>{role}</div>
    </div>
    """, unsafe_allow_html=True)
   
    if st.button("🚪 Log Out", use_container_width=True):
        st.session_state.clear()
        st.rerun()
   
    st.divider()
   
    if role == 'admin':
        st.header("⚙️ Admin")
        with st.expander("Control Panel"):
            if check_submission_window():
                st.success("🟢 Window OPEN")
                if st.button("Close Window"):
                    try:
                        db.collection("config").document("settings").set({'submission_window_open': False}, merge=True)
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error closing window: {e}")
            else:
                st.error("🔴 Window CLOSED")
                if st.button("Open Window"):
                    try:
                        db.collection("config").document("settings").set({'submission_window_open': True}, merge=True)
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error opening window: {e}")
       
        with st.expander("Add User"):
            with st.form("new_u"):
                nu = st.text_input("ID"); nn = st.text_input("Name"); np = st.text_input("Pass", type="password")
                nr = st.selectbox("Role", ["faculty","scrutinizer","approver","admin"]); nd = st.selectbox("Dept", DEPTS)
                if st.form_submit_button("Create User"):
                    if nu and np:
                        try:
                            db.collection("users").document(nu).set({'name':nn, 'password':hash_password(np), 'role':nr, 'department':nd})
                            st.success("Added!")
                        except Exception as e:
                            st.error(f"User creation error: {e}")

# --- 8. DASHBOARD TABS ---
t_inbox, t_edit, t_lib, t_cal, t_bak = st.tabs(["📥 Inbox", "📝 Editor", "📚 Library", "📅 Calendar", "💾 Backup"])

# === TAB 1: INBOX (IMPROVED: Caching, Pagination, Filters) ===
@st.cache_data(ttl=300)  # Cache 5 min
def fetch_inbox_docs(role: str, filters: dict) -> list:
    if not db:
        return []
    ref = db.collection("exams")
    query = ref
    if role == 'faculty':
        query = query.where("author_id", "==", st.session_state.user['id'])
    elif role == 'scrutinizer':
        query = query.where("status", "==", "SUBMITTED")
    elif role == 'approver':
        query = query.where("status", "==", "SCRUTINIZED")
    elif role == 'admin':
        pass
    docs = list(query.limit(50).stream())  # Limit reads
    # Client-side filter
    filtered = []
    for doc in docs:
        d = doc.to_dict()
        det = d.get('exam_details', {})
        if all(
            filters.get(k) == "All" or det.get(k) == v
            for k, v in filters.items()
        ):
            filtered.append(doc)
    return filtered

with t_inbox:
    st.markdown(f"### 📥 {role.capitalize()} Workspace")
   
    fc1, fc2, fc3, fc4 = st.columns(4)
    f_ay = fc1.selectbox("AY", ["All", "2024-2025", "2025-2026", "2023-2024"])
    f_dept = fc2.selectbox("Dept", ["All"] + DEPTS)
    f_sem = fc3.selectbox("Sem", ["All"] + SEMESTERS)
    f_type = fc4.selectbox("Exam", ["All"] + EXAM_TYPES)
    if st.button("🔄 Refresh"):
        st.cache_data.clear()
    filters = {'acadYear': f_ay, 'department': f_dept, 'semester': f_sem, 'examType': f_type}
    docs = fetch_inbox_docs(role, filters)
    
    # Pagination
    page_size = 10
    total_pages = (len(docs) + page_size - 1) // page_size
    page = st.slider("Page", 0, max(0, total_pages - 1), 0)
    paginated_docs = docs[page * page_size : (page + 1) * page_size]
    
    st.divider()
    if paginated_docs:
        for doc in paginated_docs:
            d = doc.to_dict()
            det = d.get('exam_details', {})
            status = d.get('status', 'NEW')
            badge_class = {
                "DRAFT": "badge-draft", "SUBMITTED": "badge-submitted", 
                "SCRUTINIZED": "badge-scrutinized", "APPROVED": "badge-approved", 
                "REVISION": "badge-revision"
            }.get(status, "badge-draft")
            with st.expander(f"{det.get('courseCode', 'Untitled')} - {det.get('courseName', 'N/A')}"):
                st.markdown(f"""
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <h4 style="margin:0;">{det.get('courseName', 'N/A')}</h4>
                        <p style="margin:0; color:gray; font-size:13px;">{det.get('acadYear')} | {det.get('department')} | {det.get('examType')}</p>
                    </div>
                    <span class="badge {badge_class}">{status}</span>
                </div>
                """, unsafe_allow_html=True)
               
                c1, c2 = st.columns([4, 1])
                with c1:
                    if d.get('scrutiny_comments') and role == 'faculty':
                        st.error(f"⚠️ Feedback: {d.get('scrutiny_comments')}")
                    else:
                        st.caption(f"Last Modified: {d.get('created_at', 'Unknown')}")
                with c2:
                    if st.button("📂 Open", key=f"ld_{doc.id}"):
                        st.session_state.exam_details = d['exam_details']
                        st.session_state.sections = d['sections']
                        st.session_state.current_doc_id = doc.id
                        st.session_state.current_doc_status = status
                        st.success("Loaded!")
                        st.rerun()
    else:
        st.info("No exams found.")

# === TAB 2: EDITOR (IMPROVED: Total Marks, Basic Validation) ===
with t_edit:
    read_only = role in ['approver'] or (role == 'faculty' and st.session_state.current_doc_status in ['SUBMITTED', 'APPROVED'])
    if read_only:
        st.warning("🔒 View Only Mode")
    
    with st.expander("📝 Header Details", expanded=True):
        c1, c2, c3, c4 = st.columns(4)
        st.session_state.exam_details['acadYear'] = c1.text_input("Academic Year", st.session_state.exam_details.get('acadYear', '2024-2025'), disabled=read_only)
        st.session_state.exam_details['department'] = c2.selectbox("Department", DEPTS, index=DEPTS.index(st.session_state.exam_details.get('department', 'CSE')) if st.session_state.exam_details.get('department') in DEPTS else 0, disabled=read_only)
        st.session_state.exam_details['semester'] = c3.selectbox("Semester", SEMESTERS, index=SEMESTERS.index(st.session_state.exam_details.get('semester', '1st')) if st.session_state.exam_details.get('semester') in SEMESTERS else 0, disabled=read_only)
        st.session_state.exam_details['examType'] = c4.selectbox("Exam Type", EXAM_TYPES, index=EXAM_TYPES.index(st.session_state.exam_details.get('examType', 'IA1')) if st.session_state.exam_details.get('examType') in EXAM_TYPES else 0, disabled=read_only)
       
        c1, c2, c3 = st.columns(3)
        st.session_state.exam_details['examDate'] = str(c1.date_input("Exam Date", value=datetime.datetime.strptime(st.session_state.exam_details.get('examDate', str(datetime.date.today())), "%Y-%m-%d").date(), disabled=read_only))
        st.session_state.exam_details['courseCode'] = c2.text_input("Course Code", st.session_state.exam_details.get('courseCode'), disabled=read_only)
        st.session_state.exam_details['courseName'] = c3.text_input("Course Name", st.session_state.exam_details.get('courseName'), disabled=read_only)
    
    # Basic validation on save (NEW)
    errors = validate_exam_details(st.session_state.exam_details)
    if errors:
        st.error("Validation errors: " + "; ".join(errors))
    
    st.markdown("#### Questions Editor")
    total_marks = 0
    for i, section in enumerate(st.session_state.sections):
        with st.container():
            st.markdown(f"**Block {i+1}**")
            if section.get('isNote'):
                c_del, c_txt = st.columns([1, 10])
                if not read_only and c_del.button("🗑️", key=f"dels_{section['id']}"):
                    st.session_state.sections.pop(i)
                    st.rerun()
                section['text'] = c_txt.text_input("Instruction", section['text'], key=f"n_{section['id']}", disabled=read_only)
            else:
                h1, h2 = st.columns([10, 1])
                if not read_only and h2.button("🗑️", key=f"dels_{section['id']}"):
                    st.session_state.sections.pop(i)
                    st.rerun()
               
                for j, q in enumerate(section['questions']):
                    c1, c2 = st.columns([1, 8])
                    q['qNo'] = c1.text_input("No.", q['qNo'], key=f"qn_{q['id']}", disabled=read_only)
                    q['text'] = c2.text_area("Question Text (Use $ for math)", q['text'], height=70, key=f"qt_{q['id']}", disabled=read_only)
                   
                    if q['text'].upper() != 'OR':
                        m1, m2, m3, m4 = st.columns([2,2,2,1])
                        q['marks'] = m1.number_input("M", float(q['marks']), min_value=0, key=f"mk_{q['id']}", disabled=read_only)
                        total_marks += q['marks']
                        q['co'] = m2.selectbox("CO", COS_LIST, key=f"co_{q['id']}", disabled=read_only)
                        q['level'] = m3.selectbox("L", BLOOMS_LEVELS, key=f"lv_{q['id']}", disabled=read_only)
                        if not read_only and m4.button("❌", key=f"dq_{q['id']}"):
                            section['questions'].pop(j)
                            st.rerun()
               
                if not read_only and st.button("➕ Add Question", key=f"addq_{section['id']}"):
                    section['questions'].append({'id': int(datetime.datetime.now().timestamp()*1000), 'qNo':'', 'text':'', 'marks':0, 'co':'CO1', 'level':'L1'})
                    st.rerun()
    
    st.info(f"**Total Marks: {total_marks:.0f}**")  # NEW: Auto-calc total
    
    if not read_only:
        st.divider()
        b1, b2, b3 = st.columns([1, 1, 2])
        if b1.button("➕ New Question Block"):
            st.session_state.sections.append({'id': int(datetime.datetime.now().timestamp()*1000), 'isNote': False, 'questions': [{'id': int(datetime.datetime.now().timestamp()*1000)+1, 'qNo':'', 'text':'', 'marks':0, 'co':'CO1', 'level':'L1'}]})
            st.rerun()
        if b2.button("➕ Add Note/Instruction"):
            st.session_state.sections.append({'id': int(datetime.datetime.now().timestamp()*1000), 'isNote': True, 'text': 'Note: Answer any five questions'})
            st.rerun()
    
    # Actions (IMPROVED: Check validation)
    st.markdown("### Actions")
    current_id = st.session_state.get('current_doc_id')
    d = st.session_state.exam_details
    if not current_id:
        if d['courseCode'] and d['department']:
            safe_ay = d['acadYear'].replace(" ", "")
            current_id = f"{safe_ay}_{d['department']}_{d['semester']}_{d['examType']}_{d['courseCode']}"
    
    if not d.get('courseCode'):
        st.error("⚠️ Fill Course Code before saving!")
    
    c1, c2, c3 = st.columns(3)
    if role == 'faculty' and not read_only:
        if c1.button("💾 Save Draft") and not errors:
            if db:
                data = {
                    'exam_details': d, 'sections': st.session_state.sections,
                    'status': 'DRAFT', 'author_id': st.session_state.user['id'], 'author_name': st.session_state.user['name'],
                    'created_at': str(datetime.datetime.now())
                }
                try:
                    db.collection("exams").document(current_id).set(data)
                    st.session_state.current_doc_id = current_id
                    st.success(f"Saved: {current_id}")
                except Exception as e:
                    st.error(f"Save error: {e}")
        if c2.button("📤 Submit for Review", type="primary") and current_id and not errors and check_submission_window():
            if db:
                db.collection("exams").document(current_id).update({'status': 'SUBMITTED'})
                st.session_state.current_doc_status = "SUBMITTED"
                st.success("Submitted!")
        elif not check_submission_window():
            st.error("Submission window closed!")
    
    # Other roles unchanged (for brevity)
    if role == 'scrutinizer' and st.session_state.current_doc_status == 'SUBMITTED':
        comm = st.text_area("Comments")
        if c1.button("Return for Revision") and db and current_id:
            db.collection("exams").document(current_id).update({'status':'REVISION', 'scrutiny_comments':comm})
            st.session_state.current_doc_status = "REVISION"
            st.rerun()
        if c2.button("Approve & Forward", type="primary") and db and current_id:
            db.collection("exams").document(current_id).update({'status':'SCRUTINIZED', 'exam_details.scrutinizedBy': st.session_state.user['name']})
            st.success("Approved")
            st.rerun()
    if role == 'approver' and st.session_state.current_doc_status == 'SCRUTINIZED':
        if c3.button("✅ Final Publish", type="primary") and db and current_id:
            db.collection("exams").document(current_id).update({'status':'APPROVED', 'exam_details.approvedBy': st.session_state.user['name']})
            st.success("Published!")
            st.rerun()
    
    with st.expander("👁️ Live Preview"):
        html = generate_html(st.session_state.exam_details, st.session_state.sections)
        st.components.v1.html(html, height=800, scrolling=True)

# === TAB 3: LIBRARY (IMPROVED: CSV Export, Pagination) ===
@st.cache_data(ttl=300)
def fetch_library_docs(filters: dict) -> list:
    if not db:
        return []
    query = db.collection("exams").where("status", "==", "APPROVED").limit(50)
    docs = list(query.stream())
    filtered = [doc for doc in docs if all(
        filters.get(k) == "All" or doc.to_dict().get('exam_details', {}).get(k) == v
        for k, v in filters.items()
    )]
    return filtered

with t_lib:
    st.header("📚 Exam Archive")
   
    lc1, lc2, lc3, lc4 = st.columns(4)
    l_ay = lc1.selectbox("Year", ["All", "2024-2025", "2023-2024"], key='lay')
    l_dept = lc2.selectbox("Dept", ["All"] + DEPTS, key='ld')
    l_sem = lc3.selectbox("Sem", ["All"] + SEMESTERS, key='ls')
    l_type = lc4.selectbox("Type", ["All"] + EXAM_TYPES, key='lt')
    filters = {'acadYear': l_ay, 'department': l_dept, 'semester': l_sem, 'examType': l_type}
    docs = fetch_library_docs(filters)
    
    # Pagination
    page_size = 10
    total_pages = (len(docs) + page_size - 1) // page_size
    page = st.slider("Page", 0, max(0, total_pages - 1), 0)
    paginated_docs = docs[page * page_size : (page + 1) * page_size]
    
    # NEW: CSV Export (uses pandas)
    if st.button("📊 Export to CSV"):
        export_data = []
        for doc in docs:  # Full list for export (watch reads if >50)
            d = doc.to_dict()
            det = d.get('exam_details', {})
            export_data.append({
                'ID': doc.id, 'Course Code': det.get('courseCode'), 'Course Name': det.get('courseName'),
                'Semester': det.get('semester'), 'Exam Type': det.get('examType'), 'Date': det.get('examDate'),
                'Author': d.get('author_name'), 'Status': d.get('status')
            })
        df = pd.DataFrame(export_data)
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("Download CSV", csv, "library.csv", "text/csv")
    
    for doc in paginated_docs:
        d = doc.to_dict()
        det = d.get('exam_details', {})
        with st.expander(f"{det.get('acadYear')} | {det.get('courseName')} ({det.get('examType')})"):
            c1, c2 = st.columns([3, 1])
            c1.write(f"**Date:** {det.get('examDate')} | **Author:** {d.get('author_name')}")
           
            with c2:
                html_content = generate_html(det, d['sections'])
                b64 = base64.b64encode(html_content.encode()).decode()
                href = f'<a href="data:text/html;base64,{b64}" download="{det.get("courseCode")}.html" target="_blank" style="text-decoration:none;"><button style="background-color:#4CAF50; color:white; padding:10px; border:none; cursor:pointer; font-size:16px; border-radius:5px;">📥 Download / Print</button></a>'
                st.markdown(href, unsafe_allow_html=True)

# === TAB 4: CALENDAR (Unchanged) ===
with t_cal:
    st.header("📅 Academic Schedule")
    if role == 'admin':
        with st.form("evt"):
            t = st.text_input("Title"); d = st.date_input("Date"); ty = st.selectbox("Tag", ["Exam", "Deadline", "Holiday"])
            if st.form_submit_button("Add Event") and db:
                try:
                    db.collection("events").add({'title':t, 'date':str(d), 'type':ty})
                    st.success("Added")
                except Exception as e:
                    st.error(f"Event add error: {e}")
   
    if db:
        evs = db.collection("events").order_by("date").stream()
        for e in evs:
            v = e.to_dict()
            icon = "🔴" if v['type'] == 'Exam' else "🟡" if v['type'] == 'Deadline' else "🟢"
            st.write(f"{icon} **{v['date']}**: {v['title']}")

# === TAB 5: BACKUP (IMPROVED: Error Handling) ---
with t_bak:
    st.header("💾 Backup & Restore")
    c1, c2 = st.columns(2)
    with c1:
        st.info("Plain JSON")
        js = json.dumps({'exam_details': st.session_state.exam_details, 'sections': st.session_state.sections})
        st.download_button("Download JSON", js, "backup.json")
    with c2:
        st.warning("Encrypted")
        pw = st.text_input("Password", type="password", key="bpw")
        if pw:
            try:
                k = get_key_from_password(pw)
                enc = Fernet(k).encrypt(js.encode())
                st.download_button("Download Encrypted", enc, "backup.enc")
            except Exception as e:
                st.error(f"Encryption error: {e}")
           
    st.divider()
    up = st.file_uploader("Restore File", type=['json', 'enc'])
    if up:
        if up.name.endswith('.json'):
            if st.button("Load JSON"):
                try:
                    d = json.load(up)
                    st.session_state.exam_details = d['exam_details']
                    st.session_state.sections = d['sections']
                    st.success("Loaded!")
                    st.rerun()
                except Exception as e:
                    st.error(f"JSON load error: {e}")
        elif up.name.endswith('.enc'):
            pwu = st.text_input("Unlock Pass", type="password")
            if st.button("Unlock"):
                try:
                    raw = up.read()
                    k = get_key_from_password(pwu)
                    decrypted = Fernet(k).decrypt(raw).decode()
                    d = json.loads(decrypted)
                    st.session_state.exam_details = d['exam_details']
                    st.session_state.sections = d['sections']
                    st.success("Loaded!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Decrypt error: Wrong password. {e}")

# Footer (NEW)
st.markdown("---")
st.markdown("*Downgraded for compatibility: Reverted bcrypt/Pydantic/WeasyPrint. Add to requirements.txt for full features.*")
