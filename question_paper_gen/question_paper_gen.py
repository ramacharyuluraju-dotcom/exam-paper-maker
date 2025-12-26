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

# --- 1. CONFIGURATION & CONSTANTS ---
st.set_page_config(page_title="AMC Exam Portal Pro", layout="wide", page_icon="🎓")

# Academic Constants
BLOOMS_LEVELS = ["L1", "L2", "L3", "L4", "L5", "L6"]
COS_LIST = ["CO1", "CO2", "CO3", "CO4", "CO5", "CO6"]
EXAM_TYPES = ["IA1", "IA2", "IA3", "SEE", "Makeup", "Other"]
DEPTS = ["CSE", "ECE", "MECH", "ISE", "CIVIL", "EEE", "MBA", "MCA", "Basic Science"]
SEMESTERS = ["1st", "2nd", "3rd", "4th", "5th", "6th", "7th", "8th"]

# --- 2. FIREBASE SETUP ---
if not firebase_admin._apps:
    try:
        key_dict = dict(st.secrets["firestore"])
        cred = credentials.Certificate(key_dict)
        firebase_admin.initialize_app(cred)
    except Exception as e:
        st.error(f"🔥 Firebase Error: {e}. Check your secrets.toml file!")
        st.stop()

db = firestore.client()

# --- 3. SECURITY HELPER FUNCTIONS ---
def hash_password(password):
    return hashlib.sha256(str.encode(password)).hexdigest()

def get_key_from_password(password, salt_type='new'):
    salt = b'static_salt_for_amc_exam_app' if salt_type == 'new' else b'static_salt_for_exam_app'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def login_user(username, password):
    doc = db.collection("users").document(username).get()
    if doc.exists:
        u = doc.to_dict()
        if u.get('password') == hash_password(password): return u
    return None

def check_submission_window():
    try:
        s = db.collection("config").document("settings").get()
        return s.to_dict().get('submission_window_open', True) if s.exists else True
    except: return True

# --- 4. HTML GENERATOR (MathJax + Print Ready) ---
def generate_html(details, sections):
    # Auto-generate header text
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
                    # Formatting text
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
    window.MathJax = {{
      tex: {{ inlineMath: [['$', '$'], ['\\\\(', '\\\\)']] }},
      svg: {{ fontCache: 'global' }}
    }};
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
        
        @media print {{
            body {{ padding: 0; }}
            .paper {{ box-shadow: none; margin: 0; width: 100%; }}
        }}
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

# --- 5. STATE MANAGEMENT ---
if 'user' not in st.session_state: st.session_state.user = None

# Function to Initialize/Reset Exam Data
def init_exam_data():
    return {
        'instituteName': 'AMC ENGINEERING COLLEGE', 'subHeader': '(AUTONOMOUS)',
        'accreditation': 'NAAC A+ | NBA Accredited', 'department': 'Department of CSE',
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

# --- 6. LOGIN ---
if not st.session_state.user:
    c1, c2, c3 = st.columns([1,2,1])
    with c2:
        st.title("🔐 AMC Exam Portal")
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Log In", type="primary"):
            user = login_user(u, p)
            if user:
                st.session_state.user = user; st.session_state.user['id'] = u; st.rerun()
            else: st.error("Invalid Credentials")
    st.stop()

# --- 7. SIDEBAR & LOGOUT FIX ---
with st.sidebar:
    role = st.session_state.user.get('role', 'User').lower()
    st.title(f"👤 {role.upper()}")
    st.write(f"User: **{st.session_state.user.get('name')}**")
    
    # --- FIX: CLEAR SESSION ON LOGOUT ---
    if st.button("🚪 Log Out"):
        st.session_state.clear()
        st.rerun()
    
    st.divider()
    
    if role == 'admin':
        st.header("⚙️ Admin")
        with st.expander("Control Panel"):
            if check_submission_window():
                st.success("🟢 Window OPEN")
                if st.button("Close"): db.collection("config").document("settings").set({'submission_window_open': False}, merge=True); st.rerun()
            else:
                st.error("🔴 Window CLOSED")
                if st.button("Open"): db.collection("config").document("settings").set({'submission_window_open': True}, merge=True); st.rerun()
        
        with st.expander("Add User"):
            with st.form("new_u"):
                nu = st.text_input("ID"); nn = st.text_input("Name"); np = st.text_input("Pass", type="password")
                nr = st.selectbox("Role", ["faculty","scrutinizer","approver","admin"]); nd = st.selectbox("Dept", DEPTS)
                if st.form_submit_button("Add"):
                    if nu and np: db.collection("users").document(nu).set({'name':nn, 'password':hash_password(np), 'role':nr, 'department':nd}); st.success("Added!")

# --- 8. DASHBOARD TABS ---
t_inbox, t_edit, t_lib, t_cal, t_bak = st.tabs(["📥 Inbox", "📝 Editor", "📚 Library", "📅 Calendar", "💾 Backup"])

# === TAB 1: INBOX (Filters) ===
with t_inbox:
    st.markdown(f"### 📥 {role.capitalize()} Inbox")
    
    # Filters
    fc1, fc2, fc3, fc4 = st.columns(4)
    f_ay = fc1.selectbox("Academic Year", ["All", "2024-2025", "2025-2026", "2023-2024"])
    f_dept = fc2.selectbox("Dept", ["All"] + DEPTS)
    f_sem = fc3.selectbox("Sem", ["All"] + SEMESTERS)
    f_type = fc4.selectbox("Exam", ["All"] + EXAM_TYPES)

    if st.button("🔄 Refresh Inbox"):
        docs = []
        ref = db.collection("exams")
        if role == 'faculty': docs = list(ref.where("author_id", "==", st.session_state.user['id']).stream())
        elif role == 'scrutinizer': docs = list(ref.where("status", "==", "SUBMITTED").stream())
        elif role == 'approver': docs = list(ref.where("status", "==", "SCRUTINIZED").stream())
        elif role == 'admin': docs = list(ref.stream())
        st.session_state.inbox_cache = [d for d in docs]
    
    if 'inbox_cache' in st.session_state:
        for doc in st.session_state.inbox_cache:
            d = doc.to_dict()
            det = d.get('exam_details', {})
            
            # Apply Filters
            if f_ay != "All" and det.get('acadYear') != f_ay: continue
            if f_dept != "All" and det.get('department') != f_dept: continue
            if f_sem != "All" and det.get('semester') != f_sem: continue
            if f_type != "All" and det.get('examType') != f_type: continue

            status = d.get('status', 'NEW')
            color = {"DRAFT":"grey", "SUBMITTED":"blue", "REVISION":"red", "SCRUTINIZED":"orange", "APPROVED":"green"}.get(status, 'grey')
            
            with st.expander(f"{det.get('courseCode')} | {det.get('examType')} | {status}"):
                c1, c2 = st.columns([4, 1])
                c1.write(f"**{det.get('courseName')}**")
                c1.caption(f"{det.get('acadYear')} | {det.get('department')} | {det.get('semester')} Sem | {det.get('examDate')}")
                if d.get('scrutiny_comments') and role == 'faculty': c1.error(f"Feedback: {d.get('scrutiny_comments')}")
                
                if c2.button("📂 Load", key=f"ld_{doc.id}"):
                    st.session_state.exam_details = d['exam_details']
                    st.session_state.sections = d['sections']
                    st.session_state.current_doc_id = doc.id
                    st.session_state.current_doc_status = status
                    st.success("Loaded!"); st.rerun()

# === TAB 2: EDITOR (With Organization) ===
with t_edit:
    read_only = False
    if role == 'approver' or (role == 'faculty' and st.session_state.current_doc_status in ['SUBMITTED', 'APPROVED']):
        st.warning("🔒 View Only Mode"); read_only = True

    st.subheader("1. Organization & Metadata")
    with st.container():
        c1, c2, c3, c4 = st.columns(4)
        st.session_state.exam_details['acadYear'] = c1.text_input("Academic Year", st.session_state.exam_details.get('acadYear', '2024-2025'), disabled=read_only)
        st.session_state.exam_details['department'] = c2.selectbox("Department", DEPTS, index=DEPTS.index(st.session_state.exam_details.get('department', 'CSE')) if st.session_state.exam_details.get('department') in DEPTS else 0, disabled=read_only)
        st.session_state.exam_details['semester'] = c3.selectbox("Semester", SEMESTERS, index=SEMESTERS.index(st.session_state.exam_details.get('semester', '1st')) if st.session_state.exam_details.get('semester') in SEMESTERS else 0, disabled=read_only)
        st.session_state.exam_details['examType'] = c4.selectbox("Exam Type", EXAM_TYPES, index=EXAM_TYPES.index(st.session_state.exam_details.get('examType', 'IA1')) if st.session_state.exam_details.get('examType') in EXAM_TYPES else 0, disabled=read_only)
        
        c1, c2, c3 = st.columns(3)
        st.session_state.exam_details['examDate'] = str(c1.date_input("Exam Date", value=datetime.datetime.strptime(st.session_state.exam_details.get('examDate', str(datetime.date.today())), "%Y-%m-%d").date(), disabled=read_only))
        st.session_state.exam_details['courseCode'] = c2.text_input("Course Code", st.session_state.exam_details.get('courseCode'), disabled=read_only)
        st.session_state.exam_details['courseName'] = c3.text_input("Course Name", st.session_state.exam_details.get('courseName'), disabled=read_only)

    st.divider()
    
    st.subheader("2. Questions (Supports LaTeX Math: $x^2$)")
    for i, section in enumerate(st.session_state.sections):
        st.markdown(f"**Block {i+1}**")
        if section.get('isNote'):
            c_del, c_txt = st.columns([1, 10])
            if not read_only and c_del.button("❌", key=f"dels_{section['id']}"): st.session_state.sections.pop(i); st.rerun()
            section['text'] = c_txt.text_input("Instruction", section['text'], key=f"n_{section['id']}", disabled=read_only)
        else:
            h1, h2 = st.columns([10, 1])
            if not read_only and h2.button("❌ Blk", key=f"dels_{section['id']}"): st.session_state.sections.pop(i); st.rerun()
            
            for j, q in enumerate(section['questions']):
                c1, c2 = st.columns([1, 8])
                q['qNo'] = c1.text_input("No.", q['qNo'], key=f"qn_{q['id']}", disabled=read_only)
                q['text'] = c2.text_area("Question Text (Use $ for math)", q['text'], height=70, key=f"qt_{q['id']}", disabled=read_only)
                
                if q['text'].upper() != 'OR':
                    m1, m2, m3, m4 = st.columns([2,2,2,1])
                    q['marks'] = m1.number_input("M", float(q['marks']), key=f"mk_{q['id']}", disabled=read_only)
                    q['co'] = m2.selectbox("CO", COS_LIST, key=f"co_{q['id']}", disabled=read_only)
                    q['level'] = m3.selectbox("L", BLOOMS_LEVELS, key=f"lv_{q['id']}", disabled=read_only)
                    if not read_only and m4.button("❌", key=f"dq_{q['id']}"): section['questions'].pop(j); st.rerun()
            
            if not read_only and st.button("➕ Q", key=f"addq_{section['id']}"):
                section['questions'].append({'id': int(datetime.datetime.now().timestamp()*1000), 'qNo':'', 'text':'', 'marks':0, 'co':'CO1', 'level':'L1'}); st.rerun()
        st.divider()

    if not read_only:
        b1, b2 = st.columns(2)
        if b1.button("➕ Question Block"): st.session_state.sections.append({'id': int(datetime.datetime.now().timestamp()*1000), 'isNote': False, 'questions': [{'id': int(datetime.datetime.now().timestamp()*1000)+1, 'qNo':'', 'text':'', 'marks':0, 'co':'CO1', 'level':'L1'}]}); st.rerun()
        if b2.button("➕ Instruction Note"): st.session_state.sections.append({'id': int(datetime.datetime.now().timestamp()*1000), 'isNote': True, 'text': 'Note: Answer any five questions'}); st.rerun()

    # --- ACTIONS ---
    st.markdown("### Actions")
    current_id = st.session_state.get('current_doc_id')
    
    # Auto-generate ID if not exists: AY_DEPT_SEM_TYPE_CODE
    if not current_id:
        d = st.session_state.exam_details
        if d['courseCode'] and d['department']:
            safe_ay = d['acadYear'].replace(" ", "")
            current_id = f"{safe_ay}_{d['department']}_{d['semester']}_{d['examType']}_{d['courseCode']}"

    c1, c2, c3 = st.columns(3)
    if role == 'faculty':
        if c1.button("💾 Save Draft"):
            if not d['courseCode']: st.error("Fill Header Details first!")
            else:
                data = {
                    'exam_details': st.session_state.exam_details, 'sections': st.session_state.sections,
                    'status': 'DRAFT', 'author_id': st.session_state.user['id'], 'author_name': st.session_state.user['name'],
                    'created_at': str(datetime.datetime.now())
                }
                db.collection("exams").document(current_id).set(data)
                st.session_state.current_doc_id = current_id
                st.success(f"Saved: {current_id}")

        if c2.button("📤 Submit", type="primary"):
            if not current_id: st.error("Save first")
            elif not check_submission_window(): st.error("Window Closed")
            else:
                db.collection("exams").document(current_id).update({'status': 'SUBMITTED'})
                st.session_state.current_doc_status = "SUBMITTED"
                st.success("Submitted!")

    if role == 'scrutinizer' and st.session_state.current_doc_status == 'SUBMITTED':
        comm = st.text_area("Comments")
        if c1.button("Return"): db.collection("exams").document(current_id).update({'status':'REVISION', 'scrutiny_comments':comm}); st.rerun()
        if c2.button("Approve"): db.collection("exams").document(current_id).update({'status':'SCRUTINIZED', 'exam_details.scrutinizedBy': st.session_state.user['name']}); st.success("Approved"); st.rerun()

    if role == 'approver' and st.session_state.current_doc_status == 'SCRUTINIZED':
        if c3.button("Final Approve"): db.collection("exams").document(current_id).update({'status':'APPROVED', 'exam_details.approvedBy': st.session_state.user['name']}); st.success("Published!"); st.rerun()

    with st.expander("👁️ Live Preview"):
        html = generate_html(st.session_state.exam_details, st.session_state.sections)
        st.components.v1.html(html, height=800, scrolling=True)

# === TAB 3: LIBRARY (PDF Download) ===
with t_lib:
    st.header("📚 Exam Archive")
    
    # Hierarchical Filter
    lc1, lc2, lc3, lc4 = st.columns(4)
    l_ay = lc1.selectbox("Year", ["All", "2024-2025", "2023-2024"], key='lay')
    l_dept = lc2.selectbox("Dept", ["All"] + DEPTS, key='ld')
    l_sem = lc3.selectbox("Sem", ["All"] + SEMESTERS, key='ls')
    l_type = lc4.selectbox("Type", ["All"] + EXAM_TYPES, key='lt')
    
    docs = list(db.collection("exams").where("status", "==", "APPROVED").stream())
    
    for doc in docs:
        d = doc.to_dict()
        det = d.get('exam_details', {})
        
        # Apply Filter
        if l_ay != "All" and det.get('acadYear') != l_ay: continue
        if l_dept != "All" and det.get('department') != l_dept: continue
        if l_sem != "All" and det.get('semester') != l_sem: continue
        if l_type != "All" and det.get('examType') != l_type: continue
        
        with st.expander(f"{det.get('acadYear')} | {det.get('courseName')} ({det.get('examType')})"):
            st.write(f"**Date:** {det.get('examDate')} | **Author:** {d.get('author_name')}")
            
            # --- PDF GENERATOR BUTTON ---
            # We generate the full HTML, encode it to Base64, and create a clickable button.
            # When clicked, it opens a clean print view where user hits Ctrl+P to save as PDF.
            if st.button("🖨️ Prepare PDF", key=f"pdf_{doc.id}"):
                html_content = generate_html(det, d['sections'])
                b64 = base64.b64encode(html_content.encode()).decode()
                href = f'<a href="data:text/html;base64,{b64}" download="{det.get("courseCode")}.html" target="_blank" style="text-decoration:none;"><button style="background-color:#4CAF50; color:white; padding:10px; border:none; cursor:pointer; font-size:16px;">📥 Click to Download / Print</button></a>'
                st.markdown(href, unsafe_allow_html=True)

# === TAB 4: CALENDAR ===
with t_cal:
    st.header("📅 Academic Schedule")
    if role == 'admin':
        with st.form("evt"):
            t = st.text_input("Title"); d = st.date_input("Date"); ty = st.selectbox("Tag", ["Exam", "Deadline", "Holiday"])
            if st.form_submit_button("Add"): db.collection("events").add({'title':t, 'date':str(d), 'type':ty}); st.success("Added")
    
    evs = db.collection("events").order_by("date").stream()
    for e in evs:
        v = e.to_dict()
        icon = "🔴" if v['type'] == 'Exam' else "🟡" if v['type'] == 'Deadline' else "🟢"
        st.write(f"{icon} **{v['date']}**: {v['title']}")

# === TAB 5: BACKUP ===
with t_bak:
    st.header("💾 Backup")
    c1, c2 = st.columns(2)
    with c1:
        st.caption("Plain JSON")
        js = json.dumps({'exam_details': st.session_state.exam_details, 'sections': st.session_state.sections})
        st.download_button("Download JSON", js, "backup.json")
    with c2:
        st.caption("Encrypted")
        pw = st.text_input("Password", type="password", key="bpw")
        if pw:
            try:
                k = get_key_from_password(pw, 'new')
                enc = Fernet(k).encrypt(js.encode())
                st.download_button("Download Encrypted", enc, "backup.enc")
            except: pass
            
    st.divider()
    up = st.file_uploader("Restore", type=['json', 'enc'])
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
