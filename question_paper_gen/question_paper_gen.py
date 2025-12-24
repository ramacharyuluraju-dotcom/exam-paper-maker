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
import os

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

def get_key_from_password(password):
    salt = b'static_salt_for_amc_exam_app' # In prod, store salt with file
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

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

def calculate_total_marks():
    total = 0
    for section in st.session_state.sections:
        if not section.get('isNote'):
            for q in section['questions']:
                if str(q['text']).strip().upper() != 'OR':
                    total += float(q['marks']) if q['marks'] else 0
    return total

# --- 4. HTML GENERATOR (PRO VERSION) ---
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
                    table_rows += f"""
                    <tr>
                        <td class="td-center valign-top"><b>{q['qNo']}</b></td>
                        <td class="td-left valign-top">{safe_text}</td>
                        <td class="td-center valign-top">{int(q['marks']) if q['marks'] > 0 else ''}</td>
                        <td class="td-center valign-top">{q['co']}</td>
                        <td class="td-center valign-top">{q['level']}</td>
                    </tr>"""

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <script id="MathJax-script" async src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js"></script>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Times+New+Roman:wght@400;700&family=Arial:wght@400;700&display=swap');
            body {{ font-family: 'Times New Roman', serif; color: #000; padding: 20px; }}
            .paper-container {{ width: 100%; max-width: 210mm; margin: 0 auto; background: white; }}
            
            /* Header Styles */
            .header-grid {{ display: flex; align-items: center; justify-content: center; margin-bottom: 15px; border-bottom: 2px solid #000; padding-bottom: 10px; }}
            .header-text {{ text-align: center; flex: 1; }}
            .inst-name {{ font-family: 'Arial', sans-serif; font-size: 22px; font-weight: 900; text-transform: uppercase; margin: 0; }}
            .sub-header {{ font-size: 12px; margin: 2px 0; font-weight: bold; }}
            .accreditation {{ font-size: 10px; font-style: italic; margin-top: 2px; }}

            /* USN Styles */
            .usn-wrapper {{ display: flex; justify-content: space-between; align-items: center; margin: 15px 0; }}
            .usn-boxes {{ display: flex; gap: 0; }}
            .usn-box {{ width: 25px; height: 25px; border: 1px solid #000; border-right: none; }}
            .usn-box:last-child {{ border-right: 1px solid #000; }}

            /* Meta Info */
            .meta-grid {{ width: 100%; border-top: 1px solid #000; border-bottom: 1px solid #000; padding: 10px 0; margin-bottom: 20px; font-size: 14px; display: flex; justify-content: space-between; flex-wrap: wrap; }}
            .meta-item {{ width: 48%; margin-bottom: 5px; }}

            /* Table */
            table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
            th, td {{ border: 1px solid #000; padding: 6px; }}
            .td-center {{ text-align: center; }} 
            .valign-top {{ vertical-align: top; }}
            .note-row {{ background: #f9f9f9; font-weight: bold; font-style: italic; padding: 8px; }} 
            .or-row {{ background: #eee; text-align: center; font-weight: bold; padding: 4px; }}
            
            /* Footer */
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
                <div class="usn-boxes">
                    {usn_boxes_html}
                </div>
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
                <thead>
                    <tr>
                        <th style="width: 8%;">Q.No</th>
                        <th style="width: 62%;">Questions</th>
                        <th style="width: 10%;">Marks</th>
                        <th style="width: 10%;">CO</th>
                        <th style="width: 10%;">Level</th>
                    </tr>
                </thead>
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
    return html_content

# --- 5. STATE MANAGEMENT ---
if 'user' not in st.session_state:
    st.session_state.user = None
if 'exam_details' not in st.session_state:
    st.session_state.exam_details = {
        'instituteName': 'AMC ENGINEERING COLLEGE',
        'subHeader': '(AUTONOMOUS)',
        'accreditation': 'NAAC A+ | NBA Accredited',
        'affiliation': 'Affiliated to VTU & AICTE',
        'department': 'Department of Electronics & Communication Engineering',
        'examName': 'Internal Assessment 1',
        'semester': '1st Semester B.E – Nov 2025',
        'courseName': '', 'courseCode': '', 'maxMarks': 50, 'duration': '90 Mins',
        'preparedBy': '', 'scrutinizedBy': '', 'approvedBy': ''
    }
if 'sections' not in st.session_state:
    st.session_state.sections = [{'id': 1, 'isNote': False, 'questions': [{'id': 101, 'qNo': '1.a', 'text': '', 'marks': 0, 'co': 'CO1', 'level': 'L1'}]}]
if 'current_doc_id' not in st.session_state:
    st.session_state.current_doc_id = None
if 'current_doc_status' not in st.session_state:
    st.session_state.current_doc_status = "NEW"

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
            else:
                st.error("Invalid Credentials.")
    st.stop()

# --- 7. SIDEBAR & ADMIN PANEL ---
with st.sidebar:
    role = st.session_state.user.get('role', 'User').lower()
    name = st.session_state.user.get('name', 'User')
    
    st.title(f"👤 {role.upper()}")
    st.write(f"User: **{name}**")
    
    if st.button("Log Out"):
        st.session_state.user = None
        st.rerun()
    
    st.divider()
    
    # --- ADMIN CONTROLS: Create Users ---
    if role == 'admin':
        st.header("⚙️ Admin Panel")
        
        # Submission Window Toggle
        is_open = check_submission_window()
        if is_open:
            st.success("🟢 Submissions OPEN")
            if st.button("Close Submission Window"):
                db.collection("config").document("settings").set({'submission_window_open': False}, merge=True)
                st.rerun()
        else:
            st.error("🔴 Submissions CLOSED")
            if st.button("Open Submission Window"):
                db.collection("config").document("settings").set({'submission_window_open': True}, merge=True)
                st.rerun()
        
        st.divider()
        st.subheader("Add New Faculty")
        with st.form("add_user_form"):
            new_u = st.text_input("Username (e.g. cse001)")
            new_n = st.text_input("Full Name")
            new_p = st.text_input("Password", type="password")
            new_r = st.selectbox("Role", ["faculty", "scrutinizer", "approver", "admin"])
            new_d = st.text_input("Dept (e.g. CSE)")
            if st.form_submit_button("Create User"):
                if new_u and new_p:
                    db.collection("users").document(new_u).set({
                        'name': new_n, 'password': hash_password(new_p),
                        'role': new_r, 'department': new_d
                    })
                    st.success(f"User {new_u} created!")

# --- 8. MAIN DASHBOARD ---
st.title("📋 Exam Dashboard")

# Determine Tabs based on Role
# Faculty needs Editor. Scrutinizer/Approver needs Actions.
tab_work, tab_edit, tab_view, tab_act, tab_backup = st.tabs(["📥 Inbox", "📝 Editor", "👁️ Preview", "🚀 Actions", "🔐 Backup"])

# === TAB 1: INBOX (Workflows) ===
with tab_work:
    st.markdown(f"### Pending Tasks for {role.capitalize()}")
    
    if st.button("🔄 Refresh Inbox"):
        with st.spinner("Fetching..."):
            exams_ref = db.collection("exams")
            docs = []
            
            if role == 'faculty':
                # Faculty sees: Their own Drafts or Revisions
                q1 = exams_ref.where("author_id", "==", st.session_state.user['id']).stream()
                docs = [d for d in q1] # Get all to filter locally or use composite index
            elif role == 'scrutinizer':
                # Scrutinizer sees: SUBMITTED papers (optionally filter by Dept)
                docs = list(exams_ref.where("status", "==", "SUBMITTED").stream())
            elif role == 'approver':
                # Approver sees: SCRUTINIZED papers
                docs = list(exams_ref.where("status", "==", "SCRUTINIZED").stream())
            elif role == 'admin':
                 docs = list(exams_ref.stream())
            
            st.session_state.inbox_docs = {d.id: d.to_dict() for d in docs}
            st.toast("Inbox Updated")

    if 'inbox_docs' in st.session_state and st.session_state.inbox_docs:
        for doc_id, data in st.session_state.inbox_docs.items():
            status = data.get('status', 'NEW')
            color = {"DRAFT":"grey", "SUBMITTED":"blue", "REVISION":"red", "SCRUTINIZED":"orange", "APPROVED":"green"}.get(status, 'grey')
            
            with st.expander(f"{data['exam_details'].get('courseCode', 'No Code')} : {color}[{status}]"):
                c1, c2 = st.columns([3, 1])
                c1.write(f"**Course:** {data['exam_details'].get('courseName')}")
                c1.write(f"**Author:** {data.get('author_name')}")
                if data.get('scrutiny_comments') and role == 'faculty':
                    c1.error(f"⚠️ **Scrutiny Feedback:** {data.get('scrutiny_comments')}")
                
                if c2.button("📂 Open", key=f"load_{doc_id}"):
                    st.session_state.exam_details = data['exam_details']
                    st.session_state.sections = data['sections']
                    st.session_state.current_doc_id = doc_id
                    st.session_state.current_doc_status = status
                    st.success(f"Loaded {doc_id} into Editor!")

# === TAB 2: EDITOR ===
with tab_edit:
    # Only allow editing if Faculty (Draft/Revision) OR Scrutinizer (Submitted)
    read_only = False
    if role == 'approver' or (role == 'faculty' and st.session_state.current_doc_status in ['SUBMITTED', 'APPROVED']):
        st.warning("🔒 View Only Mode (Exam is Submitted/Approved)")
        read_only = True

    # 1. Header Details
    with st.expander("🏫 Exam Header Details", expanded=False):
        c1, c2 = st.columns(2)
        st.session_state.exam_details['examName'] = c1.text_input("Exam Name", st.session_state.exam_details['examName'], disabled=read_only)
        st.session_state.exam_details['courseName'] = c1.text_input("Course Name", st.session_state.exam_details['courseName'], disabled=read_only)
        st.session_state.exam_details['courseCode'] = c2.text_input("Course Code (Unique ID)", st.session_state.exam_details['courseCode'], disabled=read_only)
        st.session_state.exam_details['maxMarks'] = c2.number_input("Max Marks", value=int(st.session_state.exam_details['maxMarks']), disabled=read_only)
        st.session_state.exam_details['duration'] = c1.text_input("Duration", st.session_state.exam_details.get('duration',''), disabled=read_only)
        
    st.divider()

    # 2. Questions
    for i, section in enumerate(st.session_state.sections):
        with st.container():
            st.markdown(f"#### Block {i+1}")
            if section.get('isNote'):
                c_del, c_txt = st.columns([1, 10])
                if not read_only and c_del.button("🗑️", key=f"del_s_{section['id']}"): 
                    st.session_state.sections.pop(i); st.rerun()
                section['text'] = c_txt.text_input("Note", section['text'], key=f"n_{section['id']}", disabled=read_only)
            else:
                h1, h2 = st.columns([9, 1])
                if not read_only and h2.button("🗑️ Blk", key=f"del_s_{section['id']}"):
                    st.session_state.sections.pop(i); st.rerun()
                
                for j, q in enumerate(section['questions']):
                    with st.expander(f"Q {q['qNo']}", expanded=True):
                        c1, c2 = st.columns([1, 6])
                        q['qNo'] = c1.text_input("No.", q['qNo'], key=f"qn_{q['id']}", disabled=read_only)
                        q['text'] = c2.text_area("Question (Use $$ for Math)", q['text'], key=f"qt_{q['id']}", height=65, disabled=read_only)
                        
                        if q['text'].strip().upper() != 'OR':
                            m1, m2, m3, m4 = st.columns([2,2,2,1])
                            q['marks'] = m1.number_input("Marks", float(q['marks']), key=f"mk_{q['id']}", disabled=read_only)
                            q['co'] = m2.selectbox("CO", COS_LIST, index=0, key=f"co_{q['id']}", disabled=read_only)
                            q['level'] = m3.selectbox("Lvl", BLOOMS_LEVELS, index=0, key=f"lv_{q['id']}", disabled=read_only)
                            if not read_only and m4.button("🗑️", key=f"dq_{q['id']}"):
                                section['questions'].pop(j); st.rerun()
                
                if not read_only and st.button("➕ Add Q", key=f"addq_{section['id']}"):
                    new_id = int(datetime.datetime.now().timestamp()*1000)
                    section['questions'].append({'id': new_id, 'qNo': '', 'text': '', 'marks': 0, 'co': 'CO1', 'level': 'L1'})
                    st.rerun()
            st.divider()

    if not read_only:
        b1, b2 = st.columns(2)
        if b1.button("➕ Add Question Block"):
            st.session_state.sections.append({'id': int(datetime.datetime.now().timestamp()*1000), 'isNote': False, 'questions': [{'id': int(datetime.datetime.now().timestamp()*1000)+1, 'qNo':'', 'text':'', 'marks':0, 'co':'CO1', 'level':'L1'}]})
            st.rerun()
        if b2.button("➕ Add Note"):
            st.session_state.sections.append({'id': int(datetime.datetime.now().timestamp()*1000), 'isNote': True, 'text': 'Note: Answer any five questions'})
            st.rerun()

# === TAB 3: PREVIEW ===
with tab_view:
    st.info("💡 To Print: Right-click -> 'Print' -> 'Save as PDF'")
    html_code = generate_html(st.session_state.exam_details, st.session_state.sections)
    st.components.v1.html(html_code, height=1000, scrolling=True)

# === TAB 4: ACTIONS (WORKFLOW) ===
with tab_act:
    st.header("🚀 Submission Workflow")
    
    current_id = st.session_state.get('current_doc_id') or st.session_state.exam_details.get('courseCode')
    status = st.session_state.get('current_doc_status', 'NEW')
    
    st.info(f"Target Exam ID: **{current_id}** | Status: **{status}**")

    # --- FACULTY ACTIONS ---
    if role == 'faculty':
        c1, c2 = st.columns(2)
        
        # 1. Save Draft
        if c1.button("💾 Save Draft to Cloud"):
            if not current_id:
                st.error("Please enter a Course Code in the Editor first.")
            else:
                data = {
                    'exam_details': st.session_state.exam_details,
                    'sections': st.session_state.sections,
                    'status': 'DRAFT', # Reset to draft on save
                    'author_id': st.session_state.user['id'],
                    'author_name': st.session_state.user.get('name'),
                    'timestamp': str(datetime.datetime.now())
                }
                db.collection("exams").document(current_id).set(data, merge=True)
                st.session_state.current_doc_id = current_id
                st.session_state.current_doc_status = 'DRAFT'
                st.success(f"Draft saved for {current_id}!")

        # 2. Submit
        if c2.button("🚀 Submit for Scrutiny", type="primary"):
            if not check_submission_window():
                st.error("Submission Window is Closed.")
            elif not current_id:
                st.error("Save Draft first.")
            else:
                db.collection("exams").document(current_id).update({'status': 'SUBMITTED'})
                st.session_state.current_doc_status = 'SUBMITTED'
                st.balloons()
                st.success("Exam Submitted successfully!")

    # --- SCRUTINIZER ACTIONS ---
    elif role == 'scrutinizer':
        if status != 'SUBMITTED':
            st.warning("You can only act on SUBMITTED papers.")
        else:
            comments = st.text_area("Review Comments (Required for rejection)")
            c1, c2 = st.columns(2)
            
            if c1.button("↩️ Reject / Return"):
                if not comments:
                    st.error("Please add comments explaining why.")
                else:
                    db.collection("exams").document(current_id).update({
                        'status': 'REVISION',
                        'scrutiny_comments': comments
                    })
                    st.success("Returned to Faculty.")
                    st.session_state.current_doc_status = 'REVISION'
            
            if c2.button("✅ Approve", type="primary"):
                db.collection("exams").document(current_id).update({
                    'status': 'SCRUTINIZED',
                    'exam_details.scrutinizedBy': st.session_state.user.get('name')
                })
                st.success("Approved! Sent to Head.")
                st.session_state.current_doc_status = 'SCRUTINIZED'

    # --- APPROVER ACTIONS ---
    elif role == 'approver':
        if status != 'SCRUTINIZED':
            st.warning("Waiting for Scrutiny completion.")
        else:
            if st.button("🏆 Final Approval (Lock Exam)", type="primary"):
                db.collection("exams").document(current_id).update({
                    'status': 'APPROVED',
                    'exam_details.approvedBy': st.session_state.user.get('name')
                })
                st.balloons()
                st.success("Exam Finalized and Locked!")
                st.session_state.current_doc_status = 'APPROVED'

# === TAB 5: HYBRID BACKUP (Plain + Secure) ===
with tab_backup:
    st.markdown("### 💾 Backup & Restore")
    st.caption("Manage your exam data. You can save plain files or password-protected files.")
    
    st.divider()
    
    # --- SECTION 1: EXPORT (Download) ---
    c1, c2 = st.columns(2)
    
    # Option A: Plain JSON (Easy)
    with c1:
        st.subheader("🔓 Plain Backup")
        st.info("Best for sharing or moving data quickly.")
        json_str = json.dumps({'exam_details': st.session_state.exam_details, 'sections': st.session_state.sections}, indent=2)
        st.download_button(
            label="Download .json (No Password)",
            data=json_str,
            file_name=f"exam_{st.session_state.exam_details.get('courseCode', 'data')}.json",
            mime="application/json"
        )

    # Option B: Encrypted (Secure)
    with c2:
        st.subheader("🔐 Secure Backup")
        st.info("Best for sensitive exam papers.")
        pass_down = st.text_input("Set Password", type="password", key="pd")
        if pass_down:
            try:
                # Prepare and Encrypt
                raw_json = json.dumps({'exam_details': st.session_state.exam_details, 'sections': st.session_state.sections})
                key = get_key_from_password(pass_down)
                enc_data = Fernet(key).encrypt(raw_json.encode())
                
                st.download_button(
                    label="Download .enc (Locked)",
                    data=enc_data,
                    file_name=f"secure_{st.session_state.exam_details.get('courseCode', 'data')}.enc",
                    mime="application/octet-stream"
                )
            except Exception as e: st.error(f"Error: {e}")
    
    st.divider()
    
    # --- SECTION 2: IMPORT (Upload) ---
    st.subheader("📂 Restore Data")
    uploaded_file = st.file_uploader("Upload .json (Plain) or .enc (Secure)", type=["json", "enc"])
    
    if uploaded_file is not None:
        file_name = uploaded_file.name
        
        # LOGIC 1: If it's a plain JSON file
        if file_name.endswith(".json"):
            st.success("📄 Plain JSON file detected.")
            if st.button("Load Data"):
                try:
                    data = json.load(uploaded_file)
                    st.session_state.exam_details = data['exam_details']
                    st.session_state.sections = data['sections']
                    st.success("Data loaded! Go to Editor.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error reading JSON: {e}")

        # LOGIC 2: If it's an Encrypted .enc file
        elif file_name.endswith(".enc"):
            st.warning("🔐 Locked file detected.")
            unlock_pass = st.text_input("Enter Password to Unlock", type="password", key="pu")
            
            if st.button("Unlock & Load"):
                try:
                    key = get_key_from_password(unlock_pass)
                    dec_data = Fernet(key).decrypt(uploaded_file.read())
                    data = json.loads(dec_data.decode())
                    
                    st.session_state.exam_details = data['exam_details']
                    st.session_state.sections = data['sections']
                    st.success("Unlocked & Loaded! Go to Editor.")
                    st.rerun()
                except:
                    st.error("❌ Incorrect Password or Corrupted File")
