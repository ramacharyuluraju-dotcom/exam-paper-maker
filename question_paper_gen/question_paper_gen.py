import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore
import hashlib
import datetime
import json
import base64
import pandas as pd
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- 1. CONFIGURATION & CONSTANTS ---
st.set_page_config(page_title="AMC Exam Portal Pro", layout="wide", page_icon="🎓")

# Academic Constants
BLOOMS_LEVELS = ["L1", "L2", "L3", "L4", "L5", "L6"]
COS_LIST = ["CO1", "CO2", "CO3", "CO4", "CO5", "CO6"]
DEPTS = ["CSE", "ECE", "MECH", "ISE", "CIVIL", "EEE", "MBA", "MCA", "Basic Science"]

# --- [THEME LOADING] ---
def load_custom_css():
    theme_color = "#fff7ed" 
    st.markdown(f"""
    <style>
        .stApp {{ background-color: {theme_color}; color: #000000 !important; font-family: 'Inter', sans-serif; }}
        section[data-testid="stSidebar"] {{ background-color: {theme_color}; border-right: 1px solid rgba(0,0,0,0.05); }}
        div[data-testid="stExpander"], div[data-testid="stForm"] {{
            background: #ffffff; border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); border: 1px solid #cbd5e1;
            padding: 20px; margin-bottom: 1rem;
        }}
        input, textarea, select {{ background-color: #ffffff !important; color: #000000 !important; border: 1px solid #cbd5e1; font-weight: 600 !important; }}
        button[kind="primary"] {{ background-color: #2563eb !important; color: white !important; border: none; }}
        .badge {{ padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 12px; }}
        .badge-draft {{ background: #e2e8f0; color: #334155; }}
        .badge-submitted {{ background: #dbeafe; color: #1e40af; }}
        .badge-scrutinized {{ background: #ffedd5; color: #9a3412; }}
        .badge-approved {{ background: #dcfce7; color: #166534; }}
        .badge-revision {{ background: #fee2e2; color: #991b1b; }}
    </style>
    """, unsafe_allow_html=True)

load_custom_css()  

# --- 2. FIREBASE SETUP ---
db = None
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
                st.error("⚠️ secrets.toml missing [firestore] section.")
                return False
        except Exception as e:
            st.error(f"🔥 Firebase Initialization Error: {e}")
            return False
    else:
        db = firestore.client()
        return True

firebase_ready = init_firebase()

# --- 3. SECURITY HELPER FUNCTIONS ---
def hash_password(password):
    return hashlib.sha256(str.encode(password)).hexdigest()

def get_key_from_password(password, salt_type='new'):
    salt = b'static_salt_for_amc_exam_app' if salt_type == 'new' else b'static_salt_for_exam_app'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def login_user(username, password):
    if not db: return None
    try:
        doc = db.collection("users").document(username).get()
        if doc.exists:
            u = doc.to_dict()
            if u.get('password') == hash_password(password): return u
    except Exception: pass
    return None

# --- 4. HTML GENERATOR (PDF View) ---
def generate_html(details, sections):
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
                    rows += f"""<tr><td style='text-align:center;'><b>{q['qNo']}</b></td><td>{txt}</td>
                    <td style='text-align:center;'>{int(q['marks']) if q['marks'] > 0 else ''}</td>
                    <td style='text-align:center;'>{q['co']}</td><td style='text-align:center;'>{q['level']}</td></tr>"""

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
    <script>window.MathJax = {{ tex: {{ inlineMath: [['$', '$'], ['\\\\(', '\\\\)']] }}, svg: {{ fontCache: 'global' }} }};</script>
    <script id="MathJax-script" async src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js"></script>
    <style>
        body {{ font-family: 'Times New Roman', serif; padding: 20px; color: #000; }}
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
                <thead><tr style="background:#f0f0f0;"><th width="8%">Q.No</th><th width="62%">Question</th><th width="10%">Marks</th><th width="10%">CO</th><th width="10%">Level</th></tr></thead>
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

# --- 5. STATE MANAGEMENT ---
if 'user' not in st.session_state: st.session_state.user = None

def init_exam_data():
    return {
        'instituteName': 'AMC ENGINEERING COLLEGE', 'subHeader': '(AUTONOMOUS)',
        'accreditation': 'NAAC A+ | NBA Accredited', 'department': '',
        'acadYear': '2024-2025', 'semester': '', 'examType': '', 'examDate': '',
        'courseName': '', 'courseCode': '', 'maxMarks': 50, 'duration': '90 Mins',
        'preparedBy': '', 'scrutinizedBy': '', 'approvedBy': '', 'scheduleId': ''
    }

if 'exam_details' not in st.session_state:
    st.session_state.exam_details = init_exam_data()
if 'sections' not in st.session_state:
    st.session_state.sections = [{'id': 1, 'isNote': False, 'questions': [{'id': 101, 'qNo': '1.a', 'text': '', 'marks': 0, 'co': 'CO1', 'level': 'L1'}]}]
if 'current_doc_id' not in st.session_state: st.session_state.current_doc_id = None
if 'current_doc_status' not in st.session_state: st.session_state.current_doc_status = "NEW"

# --- 6. LOGIN SCREEN ---
if not st.session_state.user:
    lc1, lc2, lc3 = st.columns([1, 1.5, 1]) 
    with lc2:
        with st.container():
            st.markdown("<h1 style='text-align:center;'>🎓 AMC Exam Portal</h1><hr>", unsafe_allow_html=True)
            u = st.text_input("Username", placeholder="e.g. FAC001")
            p = st.text_input("Password", type="password")
            if st.button("Secure Login", type="primary", use_container_width=True, disabled=not firebase_ready):
                user = login_user(u, p)
                if user:
                    st.session_state.user = user
                    st.session_state.user['id'] = u
                    st.rerun()
                else:
                    st.error("Invalid Credentials")
    st.stop()

# --- 7. SIDEBAR ---
with st.sidebar:
    role = st.session_state.user.get('role', 'User').lower()
    
    st.markdown(f"""
    <div style='text-align: center; padding: 10px; background: rgba(255,255,255,0.1); border-radius: 10px; margin-bottom: 20px;'>
        <div style='font-size: 40px;'>👤</div>
        <div style='font-weight: bold;'>{st.session_state.user.get('name')}</div>
        <div style='color: #64748b; font-size: 12px; text-transform: uppercase;'>{role}</div>
    </div>
    """, unsafe_allow_html=True)

    if st.button("🚪 Log Out", use_container_width=True): st.session_state.clear(); st.rerun()
    st.divider()

    if role == 'admin':
        st.header("⚙️ Admin")
        
        # --- VIEW SCHEDULES ---
        with st.expander("📋 Active Schedules", expanded=True):
            if db:
                try:
                    sch_ref = db.collection("exam_schedule").stream()
                    schedules_found = False
                    
                    for s in sch_ref:
                        schedules_found = True
                        sd = s.to_dict()
                        st.markdown(f"**{sd.get('cycle_id')}**")
                        st.caption(f"{sd.get('submission_start')} ➔ {sd.get('submission_end')}")
                        st.text(f"Subjects: {len(sd.get('subjects', []))}")
                        if st.button("🗑️", key=f"del_{s.id}"):
                            db.collection("exam_schedule").document(s.id).delete()
                            st.rerun()
                        st.divider()
                        
                    if not schedules_found: st.caption("No active cycles.")
                except Exception as e: st.error(f"DB Error: {e}")

        # --- UPLOAD SCHEDULES ---
        with st.expander("📅 Upload New Schedule"):
            st.info("Upload Time Table CSV.")
            with st.form("cycle_form"):
                cy_id = st.text_input("Cycle ID", placeholder="e.g. IA1_JAN2025")
                c1, c2 = st.columns(2)
                d_start = c1.date_input("Start")
                d_end = c2.date_input("End")
                up_csv = st.file_uploader("CSV File", type=['csv'])
                
                submitted = st.form_submit_button("🚀 Upload & Verify")
                
                if submitted:
                    if not db: st.error("No DB Connection")
                    elif not cy_id or not up_csv: st.error("Fill all fields")
                    else:
                        try:
                            df = pd.read_csv(up_csv)
                            df.columns = df.columns.str.strip().str.replace(r'[./]', '_', regex=True)
                            df = df.astype(str)
                            subjects_data = df.to_dict(orient='records')
                            
                            doc_data = {
                                'cycle_id': cy_id,
                                'submission_start': str(d_start),
                                'submission_end': str(d_end),
                                'subjects': subjects_data,
                                'created_at': str(datetime.datetime.now())
                            }
                            db.collection("exam_schedule").document(cy_id).set(doc_data)
                            st.success(f"✅ Success! Uploaded {len(subjects_data)} subjects.")
                            time.sleep(1)
                            st.rerun()
                        except Exception as e: st.error(f"❌ Error: {e}")

        with st.expander("Add User"):
            with st.form("new_u"):
                nu = st.text_input("User ID"); nn = st.text_input("Full Name"); np = st.text_input("Password", type="password")
                nr = st.selectbox("Role", ["faculty", "scrutinizer", "approver", "admin"]); nd = st.selectbox("Dept", DEPTS)
                if st.form_submit_button("Create") and db:
                    db.collection("users").document(nu).set({'name':nn, 'password':hash_password(np), 'role':nr, 'department':nd})
                    st.success("Added!")

# --- 8. DASHBOARD TABS ---
t_inbox, t_edit, t_lib, t_cal, t_bak = st.tabs(["📥 Inbox", "📝 Editor", "📚 Library", "📅 Calendar", "💾 Backup"])

# === TAB 1: INBOX ===
with t_inbox:
    st.markdown(f"### 📥 {role.capitalize()} Inbox")
    st.caption("Refresh to see latest status updates.")
    
    if st.button("🔄 Refresh Inbox") or 'inbox_cache' not in st.session_state:
        docs = []
        if db:
            ref = db.collection("exams")
            if role == 'faculty': docs = list(ref.where("author_id", "==", st.session_state.user['id']).stream())
            elif role == 'scrutinizer': docs = list(ref.where("status", "==", "SUBMITTED").stream())
            elif role == 'approver': docs = list(ref.where("status", "==", "SCRUTINIZED").stream())
            elif role == 'admin': docs = list(ref.stream())
        st.session_state.inbox_cache = docs

    if 'inbox_cache' in st.session_state:
        if not st.session_state.inbox_cache: st.info("📭 Inbox is empty.")
        for doc in st.session_state.inbox_cache:
            d = doc.to_dict()
            det = d.get('exam_details', {})
            status = d.get('status', 'NEW')
            badge = "badge-draft"
            if status == "SUBMITTED": badge = "badge-submitted"
            elif status == "SCRUTINIZED": badge = "badge-scrutinized"
            elif status == "APPROVED": badge = "badge-approved"
            elif status == "REVISION": badge = "badge-revision"

            with st.expander(f"{det.get('courseCode')} - {det.get('courseName')}"):
                st.markdown(f"<span class='badge {badge}'>{status}</span> <b>{det.get('examType')}</b> ({det.get('examDate')})", unsafe_allow_html=True)
                if d.get('scrutiny_comments'): st.error(f"Feedback: {d.get('scrutiny_comments')}")
                if st.button("📂 Open", key=f"ld_{doc.id}"):
                    st.session_state.exam_details = d['exam_details']
                    st.session_state.sections = d['sections']
                    st.session_state.current_doc_id = doc.id
                    st.session_state.current_doc_status = status
                    st.success("Loaded!")
                    st.rerun()

# === TAB 2: EDITOR (UNRESTRICTED) ===
with t_edit:
    # --- RESET BUTTON ---
    col_rst, col_fill = st.columns([1, 4])
    if col_rst.button("🆕 New Exam / Reset"):
        st.session_state.current_doc_id = None
        st.session_state.current_doc_status = "NEW"
        st.session_state.exam_details = init_exam_data()
        st.session_state.sections = [{'id': 1, 'isNote': False, 'questions': [{'id': 101, 'qNo': '1.a', 'text': '', 'marks': 0, 'co': 'CO1', 'level': 'L1'}]}]
        st.rerun()

    read_only = False
    if role == 'approver' or (role == 'faculty' and st.session_state.current_doc_status in ['SUBMITTED', 'APPROVED']):
        st.warning("🔒 View Only Mode (Exam Submitted)"); read_only = True

    with st.expander("📝 Exam Header & Settings", expanded=True):
        user_dept = st.session_state.user.get('department')
        manual_entry = False
        
        # --- DROPDOWN LOGIC (OPEN TO FACULTY & ADMIN, NO DEPT FILTER) ---
        if not read_only and role in ['faculty', 'admin']:
            manual_entry = st.toggle("✍️ Enable Manual Entry (If Schedule is missing)", value=False)
            
            if not manual_entry:
                active_subjects = []
                if db:
                    try:
                        all_cycles = db.collection("exam_schedule").stream()
                        today = datetime.date.today()
                        
                        for cy in all_cycles:
                            c_data = cy.to_dict()
                            try:
                                s_start = datetime.datetime.strptime(c_data['submission_start'].split(' ')[0], "%Y-%m-%d").date()
                                s_end = datetime.datetime.strptime(c_data['submission_end'].split(' ')[0], "%Y-%m-%d").date()
                                
                                if s_start <= today <= s_end:
                                    for s in c_data.get('subjects', []):
                                        # --- CHANGED: REMOVED DEPARTMENT FILTER ---
                                        # Now adds ALL subjects regardless of Branch/Dept column
                                        s['_cycle_id'] = c_data['cycle_id']
                                        active_subjects.append(s)
                            except Exception: continue
                    except Exception: pass

                if not active_subjects:
                    st.warning("⚠️ No active exams found in current cycle.")
                else:
                    # Sort nicely by Name
                    active_subjects = sorted(active_subjects, key=lambda x: x.get('SubName', ''))
                    
                    opts = ["-- Select --"] + [f"{s.get('SubCode','?')} : {s.get('SubName','Unknown')} ({s.get('Branch','Global')})" for s in active_subjects]
                    curr_code = st.session_state.exam_details.get('courseCode')
                    curr_idx = 0
                    if curr_code:
                        for idx, s in enumerate(active_subjects):
                            if s.get('SubCode') == curr_code: 
                                curr_idx = idx + 1
                                break
                    
                    sel = st.selectbox("📌 Select Scheduled Exam", opts, index=curr_idx)

                    if sel and sel != "-- Select --":
                        chosen = active_subjects[opts.index(sel) - 1]
                        st.session_state.exam_details.update({
                            'acadYear': chosen.get('AY'),
                            'semester': str(chosen.get('Sem')),
                            'examType': chosen.get('Type'),
                            'courseCode': chosen.get('SubCode'),
                            'courseName': chosen.get('SubName'),
                            'examDate': chosen.get('ExamDate'),
                            # Keep user's dept for record, even if subject is from another dept
                            'department': user_dept, 
                            'scheduleId': chosen.get('_cycle_id')
                        })

        # --- INPUT FIELDS ---
        input_disabled = True
        if manual_entry and not read_only: input_disabled = False
        
        c1, c2, c3, c4 = st.columns(4)
        st.session_state.exam_details['acadYear'] = c1.text_input("Academic Year", st.session_state.exam_details.get('acadYear'), disabled=input_disabled)
        st.session_state.exam_details['department'] = c2.text_input("Department", st.session_state.exam_details.get('department'), disabled=input_disabled)
        st.session_state.exam_details['semester'] = c3.text_input("Semester", st.session_state.exam_details.get('semester'), disabled=input_disabled)
        st.session_state.exam_details['examType'] = c4.text_input("Exam Type", st.session_state.exam_details.get('examType'), disabled=input_disabled)

        c1, c2, c3 = st.columns([1, 1, 2])
        st.session_state.exam_details['examDate'] = c1.text_input("Exam Date", st.session_state.exam_details.get('examDate'), disabled=input_disabled)
        st.session_state.exam_details['courseCode'] = c2.text_input("Course Code", st.session_state.exam_details.get('courseCode'), disabled=input_disabled)
        st.session_state.exam_details['courseName'] = c3.text_input("Course Name", st.session_state.exam_details.get('courseName'), disabled=input_disabled)

        st.markdown("**⚙️ Paper Settings**")
        c1, c2 = st.columns(2)
        st.session_state.exam_details['duration'] = c1.text_input("Duration", st.session_state.exam_details.get('duration'), disabled=read_only)
        st.session_state.exam_details['maxMarks'] = c2.number_input("Max Marks", value=int(st.session_state.exam_details.get('maxMarks', 50)), disabled=read_only)

    # --- QUESTIONS EDITOR ---
    st.markdown("#### Questions Editor")
    for i, section in enumerate(st.session_state.sections):
        with st.container():
            st.markdown(f"**Block {i+1}**")
            if section.get('isNote'):
                c_del, c_txt = st.columns([1, 10])
                if not read_only and c_del.button("🗑️", key=f"dels_{section['id']}"): st.session_state.sections.pop(i); st.rerun()
                section['text'] = c_txt.text_input("Instruction", section['text'], key=f"n_{section['id']}", disabled=read_only)
            else:
                h1, h2 = st.columns([10, 1])
                if not read_only and h2.button("🗑️", key=f"dels_{section['id']}"): st.session_state.sections.pop(i); st.rerun()
                
                for j, q in enumerate(section['questions']):
                    c1, c2 = st.columns([1, 8])
                    q['qNo'] = c1.text_input("No.", q['qNo'], key=f"qn_{q['id']}", disabled=read_only)
                    q['text'] = c2.text_area("Question", q['text'], height=70, key=f"qt_{q['id']}", disabled=read_only)
                    
                    if q['text'].upper() != 'OR':
                        m1, m2, m3, m4 = st.columns([2,2,2,1])
                        q['marks'] = m1.number_input("M", float(q['marks']), key=f"mk_{q['id']}", disabled=read_only)
                        q['co'] = m2.selectbox("CO", COS_LIST, key=f"co_{q['id']}", disabled=read_only)
                        q['level'] = m3.selectbox("L", BLOOMS_LEVELS, key=f"lv_{q['id']}", disabled=read_only)
                        if not read_only and m4.button("❌", key=f"dq_{q['id']}"): section['questions'].pop(j); st.rerun()
                
                if not read_only and st.button("➕ Add Question", key=f"addq_{section['id']}"):
                    section['questions'].append({'id': int(datetime.datetime.now().timestamp()*1000), 'qNo':'', 'text':'', 'marks':0, 'co':'CO1', 'level':'L1'}); st.rerun()

    if not read_only:
        st.divider()
        b1, b2 = st.columns(2)
        if b1.button("➕ New Question Block"): st.session_state.sections.append({'id': int(datetime.datetime.now().timestamp()*1000), 'isNote': False, 'questions': [{'id': int(datetime.datetime.now().timestamp()*1000)+1, 'qNo':'', 'text':'', 'marks':0, 'co':'CO1', 'level':'L1'}]}); st.rerun()
        if b2.button("➕ Add Instruction"): st.session_state.sections.append({'id': int(datetime.datetime.now().timestamp()*1000), 'isNote': True, 'text': 'Note: Answer any five questions'}); st.rerun()

    # --- ACTIONS ---
    st.markdown("### Actions")
    current_id = st.session_state.get('current_doc_id')
    
    d = st.session_state.exam_details
    if not current_id and d['courseCode']:
        safe_ay = str(d['acadYear']).replace(" ", "")
        current_id = f"{safe_ay}_{d['department']}_{d['semester']}_{d['examType']}_{d['courseCode']}"

    c1, c2, c3 = st.columns(3)
    if role in ['faculty', 'admin']:
        if c1.button("💾 Save Draft"):
            if not d['courseCode']: st.error("Select a subject first.")
            elif db:
                data = {
                    'exam_details': st.session_state.exam_details, 'sections': st.session_state.sections,
                    'status': 'DRAFT', 'author_id': st.session_state.user['id'], 'author_name': st.session_state.user['name'],
                    'created_at': str(datetime.datetime.now())
                }
                db.collection("exams").document(current_id).set(data)
                st.session_state.current_doc_id = current_id
                st.success(f"Draft Saved: {current_id}")

        if c2.button("📤 Submit for Review", type="primary"):
            if not current_id: st.error("Save Draft first")
            elif db:
                db.collection("exams").document(current_id).update({'status': 'SUBMITTED', 'exam_details.preparedBy': st.session_state.user['name']})
                st.session_state.current_doc_status = "SUBMITTED"
                st.success("Submitted successfully!")

    if role == 'scrutinizer' and st.session_state.current_doc_status == 'SUBMITTED':
        comm = st.text_area("Scrutiny Comments")
        if c1.button("Return for Revision") and db: db.collection("exams").document(current_id).update({'status':'REVISION', 'scrutiny_comments':comm}); st.rerun()
        if c2.button("Approve & Forward", type="primary") and db: db.collection("exams").document(current_id).update({'status':'SCRUTINIZED', 'exam_details.scrutinizedBy': st.session_state.user['name']}); st.success("Approved"); st.rerun()

    if role == 'approver' and st.session_state.current_doc_status == 'SCRUTINIZED':
        if c3.button("✅ Final Publish", type="primary") and db: db.collection("exams").document(current_id).update({'status':'APPROVED', 'exam_details.approvedBy': st.session_state.user['name']}); st.success("Published!"); st.rerun()

    with st.expander("👁️ Live Preview"):
        html = generate_html(st.session_state.exam_details, st.session_state.sections)
        st.components.v1.html(html, height=800, scrolling=True)

# === TAB 3: LIBRARY ===
with t_lib:
    st.header("📚 Exam Archive")
    if db:
        docs = list(db.collection("exams").where("status", "==", "APPROVED").stream())
        for doc in docs:
            d = doc.to_dict()
            det = d.get('exam_details', {})
            with st.expander(f"{det.get('acadYear')} | {det.get('courseName')}"):
                html_content = generate_html(det, d['sections'])
                b64 = base64.b64encode(html_content.encode()).decode()
                href = f'<a href="data:text/html;base64,{b64}" download="{det.get("courseCode")}.html" style="text-decoration:none;"><button style="background-color:#4CAF50;color:white;padding:8px;border-radius:5px;">📥 Download HTML/PDF</button></a>'
                st.markdown(href, unsafe_allow_html=True)

# === TAB 4: CALENDAR ===
with t_cal:
    st.header("📅 Academic Schedule")
    if role == 'admin':
        with st.form("evt"):
            t = st.text_input("Title"); d = st.date_input("Date"); ty = st.selectbox("Tag", ["Exam", "Deadline", "Holiday"])
            if st.form_submit_button("Add Event") and db: db.collection("events").add({'title':t, 'date':str(d), 'type':ty}); st.success("Added")
    
    if db:
        evs = db.collection("events").order_by("date").stream()
        for e in evs:
            v = e.to_dict()
            icon = "🔴" if v['type'] == 'Exam' else "🟡" if v['type'] == 'Deadline' else "🟢"
            st.write(f"{icon} **{v['date']}**: {v['title']}")

# === TAB 5: BACKUP ===
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
                k = get_key_from_password(pw, 'new')
                enc = Fernet(k).encrypt(js.encode())
                st.download_button("Download Encrypted", enc, "backup.enc")
            except: pass
            
    st.divider()
    up = st.file_uploader("Restore File", type=['json', 'enc'])
    if up:
        if up.name.endswith('.json'):
            if st.button("Load JSON"):
                d = json.load(up)
                st.session_state.exam_details = d['exam_details']; st.session_state.sections = d['sections']
                st.success("Loaded!"); st.rerun()
        elif up.name.endswith('.enc'):
            pwu = st.text_input("Unlock Pass", type="password")
            if st.button("Unlock"):
                try:
                    raw = up.read()
                    try: k = get_key_from_password(pwu, 'new'); d = json.loads(Fernet(k).decrypt(raw).decode())
                    except: k = get_key_from_password(pwu, 'old'); d = json.loads(Fernet(k).decrypt(raw).decode())
                    st.session_state.exam_details = d['exam_details']; st.session_state.sections = d['sections']
                    st.success("Loaded!"); st.rerun()
                except: st.error("Wrong Password")
