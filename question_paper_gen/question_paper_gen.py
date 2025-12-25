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

BLOOMS_LEVELS = ["L1", "L2", "L3", "L4", "L5", "L6"]
COS_LIST = ["CO1", "CO2", "CO3", "CO4", "CO5", "CO6"]

# --- 2. FIREBASE SETUP ---
if not firebase_admin._apps:
    try:
        # Load credentials from .streamlit/secrets.toml
        key_dict = dict(st.secrets["firestore"])
        cred = credentials.Certificate(key_dict)
        firebase_admin.initialize_app(cred)
    except Exception as e:
        st.error(f"🔥 Firebase Error: {e}. Check your secrets.toml file!")
        st.stop()

db = firestore.client()

# --- 3. HELPER FUNCTIONS ---

def hash_password(password):
    return hashlib.sha256(str.encode(password)).hexdigest()

# (Using the ROBUST flexible salt logic you provided)
def get_key_from_password(password, salt_type='new'):
    if salt_type == 'old':
        salt = b'static_salt_for_exam_app' 
    else:
        salt = b'static_salt_for_amc_exam_app'
        
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def login_user(username, password):
    doc_ref = db.collection("users").document(username)
    doc = doc_ref.get()
    if doc.exists:
        user_data = doc.to_dict()
        if user_data.get('password') == hash_password(password):
            return user_data
    return None

def check_submission_window():
    try:
        settings = db.collection("config").document("settings").get()
        if settings.exists:
            return settings.to_dict().get('submission_window_open', True)
    except:
        return True
    return True

# --- 4. HTML GENERATOR ---
def generate_html(details, sections):
    usn_boxes_html = "".join(['<div class="usn-box"></div>' for _ in range(10)])
    table_rows = ""
    for section in sections:
        if section.get('isNote'):
            table_rows += f"""<tr><td colspan="5" class="note-row">{section['text']}</td></tr>"""
        else:
            for q in section['questions']:
                if q['text'].strip().upper() == 'OR':
                    table_rows += """<tr><td colspan="5" class="or-row">OR</td></tr>"""
                else:
                    safe_text = q['text'].replace('\n', '<br>')
                    table_rows += f"""<tr><td class="td-center valign-top"><b>{q['qNo']}</b></td><td class="td-left valign-top">{safe_text}</td><td class="td-center valign-top">{int(q['marks']) if q['marks'] > 0 else ''}</td><td class="td-center valign-top">{q['co']}</td><td class="td-center valign-top">{q['level']}</td></tr>"""

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <script id="MathJax-script" async src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js"></script>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Times+New+Roman:wght@400;700&family=Arial:wght@400;700&display=swap');
            body {{ font-family: 'Times New Roman', serif; color: #000; padding: 20px; }}
            .paper-container {{ width: 100%; max-width: 210mm; margin: 0 auto; background: white; }}
            .header-grid {{ display: flex; align-items: center; justify-content: center; margin-bottom: 15px; border-bottom: 2px solid #000; padding-bottom: 10px; }}
            .header-text {{ text-align: center; flex: 1; }}
            .inst-name {{ font-family: 'Arial', sans-serif; font-size: 22px; font-weight: 900; text-transform: uppercase; margin: 0; }}
            .sub-header {{ font-size: 12px; margin: 2px 0; font-weight: bold; }}
            .accreditation {{ font-size: 10px; font-style: italic; margin-top: 2px; }}
            .usn-wrapper {{ display: flex; justify-content: space-between; align-items: center; margin: 15px 0; }}
            .usn-boxes {{ display: flex; gap: 0; }}
            .usn-box {{ width: 25px; height: 25px; border: 1px solid #000; border-right: none; }}
            .usn-box:last-child {{ border-right: 1px solid #000; }}
            .meta-grid {{ width: 100%; border-top: 1px solid #000; border-bottom: 1px solid #000; padding: 10px 0; margin-bottom: 20px; font-size: 14px; display: flex; justify-content: space-between; flex-wrap: wrap; }}
            .meta-item {{ width: 48%; margin-bottom: 5px; }}
            table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
            th, td {{ border: 1px solid #000; padding: 6px; }}
            .td-center {{ text-align: center; }} .valign-top {{ vertical-align: top; }}
            .note-row {{ background: #f9f9f9; font-weight: bold; font-style: italic; padding: 8px; }} 
            .or-row {{ background: #eee; text-align: center; font-weight: bold; padding: 4px; }}
            .footer-grid {{ display: flex; justify-content: space-between; margin-top: 60px; }}
            .sig-line {{ border-top: 1px solid #000; width: 150px; text-align: center; padding-top: 5px; font-size: 12px; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="paper-container">
            <div class="header-grid">
                <div class="header-text">
                    <div class="inst-name">{details.get('instituteName', 'INSTITUTE NAME')}</div>
                    <div class="sub-header">{details.get('subHeader', '')}</div>
                    <div class="sub-header">{details.get('department', '')}</div>
                    <div class="accreditation">{details.get('accreditation', '')} | {details.get('affiliation', '')}</div>
                </div>
            </div>
            <div class="usn-wrapper">
                <span style="font-weight: bold; font-size: 16px;">USN</span>
                <div class="usn-boxes">{usn_boxes_html}</div>
            </div>
            <div style="text-align: center; font-weight: bold; font-size: 16px; margin-bottom: 15px; text-decoration: underline;">
                {details.get('examName', '')} - {details.get('semester', '')}
            </div>
            <div class="meta-grid">
                <div class="meta-item"><b>Course:</b> {details.get('courseName', '')}</div>
                <div class="meta-item"><b>Max Marks:</b> {details.get('maxMarks', '')}</div>
                <div class="meta-item"><b>Code:</b> {details.get('courseCode', '')}</div>
                <div class="meta-item"><b>Duration:</b> {details.get('duration', '')}</div>
            </div>
            <table>
                <thead><tr><th style="width: 8%;">Q.No</th><th style="width: 62%;">Questions</th><th style="width: 10%;">Marks</th><th style="width: 10%;">CO</th><th style="width: 10%;">Level</th></tr></thead>
                <tbody>{table_rows}</tbody>
            </table>
            <div class="footer-grid">
                <div><div class="sig-line">{details.get('preparedBy', '')}<br>Prepared By</div></div>
                <div><div class="sig-line">{details.get('scrutinizedBy', '')}<br>Scrutinized By</div></div>
                <div><div class="sig-line">{details.get('approvedBy', '')}<br>Approved By</div></div>
            </div>
        </div>
    </body>
    </html>
    """

# --- 5. STATE MANAGEMENT ---
if 'user' not in st.session_state: st.session_state.user = None
if 'exam_details' not in st.session_state:
    st.session_state.exam_details = {
        'instituteName': 'AMC ENGINEERING COLLEGE', 'subHeader': '(AUTONOMOUS)',
        'accreditation': 'NAAC A+ | NBA Accredited', 'affiliation': 'Affiliated to VTU & AICTE',
        'department': 'Department of Electronics & Communication Engineering',
        'examName': 'Internal Assessment 1', 'semester': '1st Semester B.E – Nov 2025',
        'courseName': '', 'courseCode': '', 'maxMarks': 50, 'duration': '90 Mins',
        'preparedBy': '', 'scrutinizedBy': '', 'approvedBy': ''
    }
if 'sections' not in st.session_state:
    st.session_state.sections = [{'id': 1, 'isNote': False, 'questions': [{'id': 101, 'qNo': '1.a', 'text': '', 'marks': 0, 'co': 'CO1', 'level': 'L1'}]}]
if 'current_doc_id' not in st.session_state: st.session_state.current_doc_id = None
if 'current_doc_status' not in st.session_state: st.session_state.current_doc_status = "NEW"

# --- 6. LOGIN SCREEN ---
if not st.session_state.user:
    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        st.title("🔐 AMC Exam Portal")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Log In", type="primary"):
            user_blob = login_user(username, password)
            if user_blob:
                st.session_state.user = user_blob
                st.session_state.user['id'] = username
                st.rerun()
            else: st.error("Invalid Credentials.")
    st.stop()

# --- 7. SIDEBAR ---
with st.sidebar:
    role = st.session_state.user.get('role', 'User').lower()
    name = st.session_state.user.get('name', 'User')
    st.title(f"👤 {role.upper()}")
    st.write(f"User: **{name}**")
    if st.button("Log Out"): st.session_state.user = None; st.rerun()
    st.divider()
    
    if role == 'admin':
        st.header("⚙️ Admin Panel")
        with st.expander("Submission Control"):
            is_open = check_submission_window()
            if is_open:
                st.success("🟢 Submissions OPEN")
                if st.button("Close Window"): db.collection("config").document("settings").set({'submission_window_open': False}, merge=True); st.rerun()
            else:
                st.error("🔴 Submissions CLOSED")
                if st.button("Open Window"): db.collection("config").document("settings").set({'submission_window_open': True}, merge=True); st.rerun()
        
        with st.expander("Add Faculty"):
            with st.form("add_user_form"):
                nu = st.text_input("Username"); nn = st.text_input("Name"); np = st.text_input("Password", type="password")
                nr = st.selectbox("Role", ["faculty", "scrutinizer", "approver", "admin"]); nd = st.text_input("Dept (e.g. CSE)")
                if st.form_submit_button("Create User"):
                    if nu and np:
                        db.collection("users").document(nu).set({'name': nn, 'password': hash_password(np), 'role': nr, 'department': nd})
                        st.success(f"User {nu} created!")

# --- 8. DASHBOARD TABS ---
# Added Library and Calendar tabs
tab_work, tab_edit, tab_lib, tab_cal, tab_backup = st.tabs(["📥 Inbox", "📝 Editor", "📚 Library", "📅 Calendar", "💾 Backup"])

# === TAB 1: INBOX ===
with tab_work:
    st.markdown(f"### Tasks for {role.capitalize()}")
    c1, c2 = st.columns([3, 1])
    # Filters
    filter_dept = c1.selectbox("Filter Dept", ["All", "CSE", "ECE", "MECH", "ISE", "Basic Science"])
    if c2.button("🔄 Refresh"):
        with st.spinner("Fetching..."):
            exams_ref = db.collection("exams")
            docs = []
            if role == 'faculty': q1 = exams_ref.where("author_id", "==", st.session_state.user['id']).stream(); docs = [d for d in q1]
            elif role == 'scrutinizer': docs = list(exams_ref.where("status", "==", "SUBMITTED").stream())
            elif role == 'approver': docs = list(exams_ref.where("status", "==", "SCRUTINIZED").stream())
            elif role == 'admin': docs = list(exams_ref.stream())
            st.session_state.inbox_docs = {d.id: d.to_dict() for d in docs}
            st.toast("Updated")

    if 'inbox_docs' in st.session_state:
        for doc_id, data in st.session_state.inbox_docs.items():
            # Apply Dept Filter
            if filter_dept != "All" and data.get('meta_dept') != filter_dept: continue
            
            status = data.get('status', 'NEW')
            color = {"DRAFT":"grey", "SUBMITTED":"blue", "REVISION":"red", "SCRUTINIZED":"orange", "APPROVED":"green"}.get(status, 'grey')
            with st.expander(f"{data['exam_details'].get('courseCode', 'No Code')} : {color}[{status}]"):
                c1, c2 = st.columns([3, 1])
                c1.write(f"**Subject:** {data['exam_details'].get('courseName')} | **Author:** {data.get('author_name')}")
                if data.get('scrutiny_comments') and role == 'faculty': c1.error(f"⚠️ Feedback: {data.get('scrutiny_comments')}")
                if c2.button("📂 Load", key=f"load_{doc_id}"):
                    st.session_state.exam_details = data['exam_details']
                    st.session_state.sections = data['sections']
                    st.session_state.current_doc_id = doc_id
                    st.session_state.current_doc_status = status
                    st.success(f"Loaded {doc_id}!"); st.rerun()

# === TAB 2: EDITOR (With Save/Submit inside) ===
with tab_edit:
    read_only = False
    if role == 'approver' or (role == 'faculty' and st.session_state.current_doc_status in ['SUBMITTED', 'APPROVED']):
        st.warning("🔒 View Only Mode"); read_only = True

    with st.expander("📌 Exam Details (Must fill for Saving)", expanded=True):
        c1, c2 = st.columns(2)
        st.session_state.exam_details['examName'] = c1.text_input("Exam Name", st.session_state.exam_details['examName'], disabled=read_only)
        st.session_state.exam_details['courseCode'] = c2.text_input("Course Code (ID)", st.session_state.exam_details['courseCode'], disabled=read_only)
        st.session_state.exam_details['courseName'] = c1.text_input("Course Name", st.session_state.exam_details['courseName'], disabled=read_only)
        st.session_state.exam_details['department'] = c2.selectbox("Department", ["CSE", "ECE", "MECH", "ISE", "Basic Science"], index=1, disabled=read_only)
        st.session_state.exam_details['maxMarks'] = c1.number_input("Marks", value=int(st.session_state.exam_details['maxMarks']), disabled=read_only)
        
    st.divider()

    # Question Editor
    for i, section in enumerate(st.session_state.sections):
        with st.container():
            st.markdown(f"#### Block {i+1}")
            if section.get('isNote'):
                c_del, c_txt = st.columns([1, 10])
                if not read_only and c_del.button("🗑️", key=f"del_s_{section['id']}"): st.session_state.sections.pop(i); st.rerun()
                section['text'] = c_txt.text_input("Note", section['text'], key=f"n_{section['id']}", disabled=read_only)
            else:
                h1, h2 = st.columns([9, 1])
                if not read_only and h2.button("🗑️ Blk", key=f"del_s_{section['id']}"): st.session_state.sections.pop(i); st.rerun()
                for j, q in enumerate(section['questions']):
                    c1, c2 = st.columns([1, 6])
                    q['qNo'] = c1.text_input("No.", q['qNo'], key=f"qn_{q['id']}", disabled=read_only)
                    q['text'] = c2.text_area("Question", q['text'], key=f"qt_{q['id']}", height=65, disabled=read_only)
                    if q['text'].strip().upper() != 'OR':
                        m1, m2, m3 = st.columns([1,1,1])
                        q['marks'] = m1.number_input("Marks", float(q['marks']), key=f"mk_{q['id']}", disabled=read_only)
                        q['co'] = m2.selectbox("CO", COS_LIST, key=f"co_{q['id']}", disabled=read_only)
                        q['level'] = m3.selectbox("Lvl", BLOOMS_LEVELS, key=f"lv_{q['id']}", disabled=read_only)
    
            if not read_only and st.button("➕ Add Q", key=f"addq_{section['id']}"):
                section['questions'].append({'id': int(datetime.datetime.now().timestamp()*1000), 'qNo': '', 'text': '', 'marks': 0, 'co': 'CO1', 'level': 'L1'}); st.rerun()
            st.divider()

    if not read_only:
        b1, b2 = st.columns(2)
        if b1.button("➕ Add Block"): st.session_state.sections.append({'id': int(datetime.datetime.now().timestamp()*1000), 'isNote': False, 'questions': [{'id': int(datetime.datetime.now().timestamp()*1000)+1, 'qNo':'', 'text':'', 'marks':0, 'co':'CO1', 'level':'L1'}]}); st.rerun()
        if b2.button("➕ Add Note"): st.session_state.sections.append({'id': int(datetime.datetime.now().timestamp()*1000), 'isNote': True, 'text': 'Note: Answer any five questions'}); st.rerun()

    # --- SAVE & SUBMIT ACTIONS ---
    st.markdown("### 🚀 Actions")
    # Identify the Exam ID clearly
    exam_id = st.session_state.exam_details.get('courseCode')
    dept = st.session_state.exam_details.get('department')
    
    # Generate a proper Document ID for Firestore
    if exam_id and dept:
        doc_key = f"{exam_id}_{dept}"
    else:
        doc_key = None

    c1, c2, c3 = st.columns(3)
    
    # 1. SAVE DRAFT (Faculty)
    if role == 'faculty':
        if c1.button("💾 Save Draft"):
            if not doc_key: st.error("❌ Enter Course Code and Dept first!")
            else:
                data = {
                    'exam_details': st.session_state.exam_details, 'sections': st.session_state.sections,
                    'status': 'DRAFT', 'author_id': st.session_state.user['id'], 'author_name': st.session_state.user['name'],
                    'meta_dept': dept, 'created_at': str(datetime.datetime.now())
                }
                db.collection("exams").document(doc_key).set(data)
                st.session_state.current_doc_id = doc_key
                st.success(f"✅ Saved as {doc_key}")

        # 2. SUBMIT (Faculty)
        if c2.button("📤 Submit for Scrutiny", type="primary"):
            if not doc_key: st.error("Save Draft first!")
            elif not check_submission_window(): st.error("Submission Window Closed!")
            else:
                db.collection("exams").document(doc_key).update({'status': 'SUBMITTED'})
                st.session_state.current_doc_status = "SUBMITTED"
                st.balloons(); st.success("Submitted successfully!")

    # 3. SCRUTINY & APPROVAL
    if role == 'scrutinizer' and st.session_state.current_doc_status == 'SUBMITTED':
        comments = st.text_area("Comments")
        if c1.button("↩️ Return"): db.collection("exams").document(doc_key).update({'status': 'REVISION', 'scrutiny_comments': comments}); st.rerun()
        if c2.button("✅ Approve"): db.collection("exams").document(doc_key).update({'status': 'SCRUTINIZED'}); st.success("Forwarded"); st.rerun()

    if role == 'approver' and st.session_state.current_doc_status == 'SCRUTINIZED':
        if c3.button("🏆 Final Approve"): db.collection("exams").document(doc_key).update({'status': 'APPROVED'}); st.success("Published to Library!"); st.rerun()
    
    # Preview HTML
    with st.expander("👁️ Live Preview"):
        html_code = generate_html(st.session_state.exam_details, st.session_state.sections)
        st.components.v1.html(html_code, height=800, scrolling=True)

# === TAB 3: LIBRARY (Past Papers) ===
with tab_lib:
    st.header("📚 Exam Library")
    st.caption("Download Approved Question Papers")
    
    # Only fetch APPROVED exams
    docs = db.collection("exams").where("status", "==", "APPROVED").stream()
    
    for doc in docs:
        d = doc.to_dict()
        with st.expander(f"📄 {d['exam_details']['courseName']} ({d['exam_details']['courseCode']})"):
            st.write(f"**Dept:** {d.get('meta_dept')} | **Date:** {d.get('created_at', '')[:10]}")
            if st.button("👁️ View", key=f"view_lib_{doc.id}"):
                html = generate_html(d['exam_details'], d['sections'])
                st.components.v1.html(html, height=600, scrolling=True)

# === TAB 4: CALENDAR ===
with tab_cal:
    st.header("📅 Academic Calendar")
    if role == 'admin':
        with st.form("add_event"):
            et = st.text_input("Event Title"); ed = st.date_input("Date"); etype = st.selectbox("Type", ["Pre-Exam", "Exam", "Post-Exam"])
            if st.form_submit_button("Add Event"):
                db.collection("events").add({'title':et, 'date':str(ed), 'type':etype}); st.success("Added!")
    
    st.divider()
    events = db.collection("events").order_by("date").stream()
    for e in events:
        ev = e.to_dict()
        st.write(f"**{ev['date']}** : {ev['title']} ({ev['type']})")

# === TAB 5: BACKUP (Hybrid) ===
with tab_backup:
    st.header("💾 Backup / Restore")
    c1, c2 = st.columns(2)
    
    # PLAIN JSON
    with c1:
        st.subheader("🔓 Plain JSON")
        json_str = json.dumps({'exam_details': st.session_state.exam_details, 'sections': st.session_state.sections}, indent=2)
        st.download_button("Download .json", json_str, "backup.json")
        
    # ENCRYPTED
    with c2:
        st.subheader("🔐 Encrypted")
        pw = st.text_input("Password", type="password", key="enc_pw")
        if pw:
            try:
                raw = json.dumps({'exam_details': st.session_state.exam_details, 'sections': st.session_state.sections})
                key = get_key_from_password(pw, 'new')
                enc = Fernet(key).encrypt(raw.encode())
                st.download_button("Download .enc", enc, "backup.enc")
            except: st.error("Error encrypting")

    st.divider()
    st.subheader("Restore")
    up = st.file_uploader("Upload .json or .enc", type=['json', 'enc'])
    
    if up:
        if up.name.endswith(".json"):
            if st.button("Load JSON"):
                d = json.load(up)
                st.session_state.exam_details = d['exam_details']; st.session_state.sections = d['sections']
                st.success("Loaded!"); st.rerun()
        elif up.name.endswith(".enc"):
            pw_unlock = st.text_input("Unlock Password", type="password", key="dec_pw")
            if st.button("Unlock"):
                try:
                    bytes_data = up.read()
                    # Try New Salt
                    try:
                        key = get_key_from_password(pw_unlock, 'new')
                        d = json.loads(Fernet(key).decrypt(bytes_data).decode())
                    except:
                        # Try Old Salt
                        key = get_key_from_password(pw_unlock, 'old')
                        d = json.loads(Fernet(key).decrypt(bytes_data).decode())
                    
                    st.session_state.exam_details = d['exam_details']; st.session_state.sections = d['sections']
                    st.success("Unlocked & Loaded!"); st.rerun()
                except: st.error("Wrong Password")
