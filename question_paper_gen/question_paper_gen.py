import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore
import hashlib
import datetime
import json
import base64

# --- 1. CONFIGURATION & CONSTANTS ---
st.set_page_config(page_title="AMC Exam Portal Pro", layout="wide", page_icon="🎓")

BLOOMS_LEVELS = ["L1", "L2", "L3", "L4", "L5", "L6"]
COS_LIST = ["CO1", "CO2", "CO3", "CO4", "CO5", "CO6"]

# --- 2. FIREBASE SETUP (Singleton) ---
if not firebase_admin._apps:
    # Load credentials from .streamlit/secrets.toml
    cred = credentials.Certificate(dict(st.secrets["firestore"]))
    firebase_admin.initialize_app(cred)

db = firestore.client()

# --- 3. HELPER FUNCTIONS ---

def hash_password(password):
    return hashlib.sha256(str.encode(password)).hexdigest()

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

# --- 4. HTML GENERATOR (The "Pro" Feature) ---
def generate_html(details, sections):
    # (This is the high-quality HTML template from your request)
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
                        <td class="td-center valing-top"><b>{q['qNo']}</b></td>
                        <td class="td-left valing-top">{safe_text}</td>
                        <td class="td-center valing-top">{int(q['marks']) if q['marks'] > 0 else ''}</td>
                        <td class="td-center valing-top">{q['co']}</td>
                        <td class="td-center valing-top">{q['level']}</td>
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
            .header-grid {{ text-align: center; border-bottom: 2px solid #000; padding-bottom: 10px; margin-bottom: 20px; }}
            .inst-name {{ font-family: 'Arial', sans-serif; font-size: 22px; font-weight: 900; text-transform: uppercase; }}
            .sub-header {{ font-size: 14px; font-weight: bold; margin: 2px 0; }}
            .meta-grid {{ border-top: 1px solid #000; border-bottom: 1px solid #000; padding: 10px 0; margin-bottom: 20px; display: flex; justify-content: space-between; flex-wrap: wrap; }}
            .meta-item {{ width: 48%; font-size: 14px; margin-bottom: 5px; }}
            table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
            th, td {{ border: 1px solid #000; padding: 6px; }}
            .td-center {{ text-align: center; }} .note-row {{ background: #f9f9f9; font-weight: bold; font-style: italic; }} .or-row {{ background: #eee; text-align: center; font-weight: bold; }}
            .footer-grid {{ display: flex; justify-content: space-between; margin-top: 50px; }}
            .sig-line {{ border-top: 1px solid #000; width: 150px; text-align: center; padding-top: 5px; font-size: 12px; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="paper-container">
            <div class="header-grid">
                <div class="inst-name">{details.get('instituteName', 'INSTITUTE NAME')}</div>
                <div class="sub-header">{details.get('subHeader', '')}</div>
                <div class="sub-header">{details.get('department', '')}</div>
                <div style="font-size: 10px; margin-top: 5px;">{details.get('accreditation', '')}</div>
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
        'department': 'Department of CSE',
        'examName': 'Internal Assessment 1',
        'semester': '5th Semester - Nov 2025',
        'courseName': '', 'courseCode': '', 'maxMarks': 50, 'duration': '90 Mins',
        'preparedBy': '', 'scrutinizedBy': '', 'approvedBy': ''
    }
if 'sections' not in st.session_state:
    st.session_state.sections = [{'id': 1, 'isNote': False, 'questions': [{'id': 101, 'qNo': '1.a', 'text': '', 'marks': 0, 'co': 'CO1', 'level': 'L1'}]}]

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
                st.error("Invalid Credentials")
    st.stop()

# --- 7. SIDEBAR (User Info) ---
with st.sidebar:
    st.title(f"👤 {st.session_state.user['role'].upper()}")
    # Use .get() to provide a default value if 'name' is missing
st.write(f"User: **{st.session_state.user.get('name', 'Admin User')}**")
    if st.button("Log Out"):
        st.session_state.user = None
        st.rerun()
    st.divider()
    
    # Admin Toggle
    if st.session_state.user['role'] == 'admin':
        st.header("⚙️ Admin")
        is_open = check_submission_window()
        if is_open:
            st.success("🟢 Window OPEN")
            if st.button("Close Window"):
                db.collection("config").document("settings").set({'submission_window_open': False}, merge=True)
                st.rerun()
        else:
            st.error("🔴 Window CLOSED")
            if st.button("Open Window"):
                db.collection("config").document("settings").set({'submission_window_open': True}, merge=True)
                st.rerun()

# --- 8. MAIN DASHBOARD ---
st.title("📋 Exam Dashboard")

# The 4 Main Tabs
tab_work, tab_edit, tab_view, tab_act = st.tabs(["📥 Workspace", "📝 Editor", "👁️ Preview", "🚀 Actions"])

# === TAB 1: WORKSPACE (Inbox) ===
with tab_work:
    role = st.session_state.user['role']
    st.markdown(f"### Pending Tasks for {role.capitalize()}")
    
    if st.button("🔄 Refresh Inbox"):
        with st.spinner("Fetching..."):
            exams_ref = db.collection("exams")
            docs = []
            if role == 'faculty':
                # Faculty see drafts and returns
                q1 = exams_ref.where("author_id", "==", st.session_state.user['id']).where("status", "in", ["DRAFT", "REVISION"]).stream()
                docs = list(q1)
            elif role == 'scrutinizer':
                # Scrutinizers see SUBMITTED
                docs = list(exams_ref.where("status", "==", "SUBMITTED").stream())
            elif role == 'approver':
                # Approvers see SCRUTINIZED
                docs = list(exams_ref.where("status", "==", "SCRUTINIZED").stream())
            
            st.session_state.inbox_docs = {d.id: d.to_dict() for d in docs}
            st.toast("Inbox Updated")

    if 'inbox_docs' in st.session_state and st.session_state.inbox_docs:
        for doc_id, data in st.session_state.inbox_docs.items():
            color = {"DRAFT":"grey", "SUBMITTED":"blue", "REVISION":"red", "SCRUTINIZED":"orange", "APPROVED":"green"}.get(data.get('status'), 'grey')
            with st.expander(f"{data['exam_details']['courseCode']} :{color}[{data.get('status')}]"):
                c1, c2 = st.columns([3, 1])
                c1.write(f"**Modified:** {data.get('timestamp')}")
                if data.get('scrutiny_comments') and role == 'faculty':
                    c1.error(f"⚠️ **Comments:** {data.get('scrutiny_comments')}")
                
                if c2.button("📂 Load", key=f"load_{doc_id}"):
                    st.session_state.exam_details = data['exam_details']
                    st.session_state.sections = data['sections']
                    st.session_state.current_doc_id = doc_id
                    st.session_state.current_doc_status = data.get('status')
                    st.success("Loaded! Go to Editor.")

# === TAB 2: EDITOR (The Pro UI) ===
with tab_edit:
    # 1. Header Details
    with st.expander("🏫 Exam Header Details", expanded=False):
        c1, c2 = st.columns(2)
        st.session_state.exam_details['examName'] = c1.text_input("Exam Name", st.session_state.exam_details['examName'])
        st.session_state.exam_details['courseName'] = c1.text_input("Course Name", st.session_state.exam_details['courseName'])
        st.session_state.exam_details['courseCode'] = c2.text_input("Course Code", st.session_state.exam_details['courseCode'])
        st.session_state.exam_details['maxMarks'] = c2.number_input("Max Marks", value=int(st.session_state.exam_details['maxMarks']))
        # Auto-fill names based on workflow
        if role == 'faculty': st.session_state.exam_details['preparedBy'] = st.session_state.user['name']
        
    st.divider()

    # 2. Marks Check
    curr_total = calculate_total_marks()
    max_m = st.session_state.exam_details['maxMarks']
    if curr_total > max_m: st.error(f"⚠️ Total ({curr_total}) > Max ({max_m})")
    elif curr_total < max_m: st.warning(f"⚠️ Total ({curr_total}) < Max ({max_m})")
    else: st.success(f"✅ Marks Balanced: {curr_total}/{max_m}")

    # 3. Question Blocks
    for i, section in enumerate(st.session_state.sections):
        with st.container():
            st.markdown(f"#### Block {i+1}")
            if section.get('isNote'):
                c_del, c_txt = st.columns([1, 10])
                if c_del.button("🗑️", key=f"del_s_{section['id']}"): 
                    st.session_state.sections.pop(i); st.rerun()
                section['text'] = c_txt.text_input("Note", section['text'], key=f"n_{section['id']}")
            else:
                h1, h2 = st.columns([9, 1])
                if h2.button("🗑️ Blk", key=f"del_s_{section['id']}"):
                    st.session_state.sections.pop(i); st.rerun()
                
                for j, q in enumerate(section['questions']):
                    with st.expander(f"Q {q['qNo']}", expanded=True):
                        c1, c2 = st.columns([1, 6])
                        q['qNo'] = c1.text_input("No.", q['qNo'], key=f"qn_{q['id']}")
                        q['text'] = c2.text_area("Question", q['text'], key=f"qt_{q['id']}", height=65)
                        
                        if q['text'].strip().upper() != 'OR':
                            m1, m2, m3, m4 = st.columns([2,2,2,1])
                            q['marks'] = m1.number_input("Marks", float(q['marks']), key=f"mk_{q['id']}")
                            q['co'] = m2.selectbox("CO", COS_LIST, index=0, key=f"co_{q['id']}")
                            q['level'] = m3.selectbox("Lvl", BLOOMS_LEVELS, index=0, key=f"lv_{q['id']}")
                            if m4.button("🗑️", key=f"dq_{q['id']}"):
                                section['questions'].pop(j); st.rerun()
                
                if st.button("➕ Add Q", key=f"addq_{section['id']}"):
                    new_id = int(datetime.datetime.now().timestamp()*1000)
                    section['questions'].append({'id': new_id, 'qNo': '', 'text': '', 'marks': 0, 'co': 'CO1', 'level': 'L1'})
                    st.rerun()
            st.divider()

    # 4. Add Section Buttons
    b1, b2 = st.columns(2)
    if b1.button("➕ Add Question Block"):
        st.session_state.sections.append({'id': int(datetime.datetime.now().timestamp()*1000), 'isNote': False, 'questions': [{'id': int(datetime.datetime.now().timestamp()*1000)+1, 'qNo':'', 'text':'', 'marks':0, 'co':'CO1', 'level':'L1'}]})
        st.rerun()
    if b2.button("➕ Add Note"):
        st.session_state.sections.append({'id': int(datetime.datetime.now().timestamp()*1000), 'isNote': True, 'text': 'Note: Answer any five questions'})
        st.rerun()

# === TAB 3: PREVIEW (HTML) ===
with tab_view:
    st.info("💡 To Print: Right-click inside the white box -> 'Print' -> 'Save as PDF'")
    html_code = generate_html(st.session_state.exam_details, st.session_state.sections)
    st.components.v1.html(html_code, height=800, scrolling=True)

# === TAB 4: ACTIONS (Cloud Workflow) ===
with tab_act:
    st.header("🚀 Submission & Workflow")
    
    doc_id = st.session_state.get('current_doc_id')
    status = st.session_state.get('current_doc_status', 'NEW')
    
    st.info(f"Current Status: **{status}**")
    
    # 1. FACULTY CONTROLS
    if role == 'faculty':
        new_id_inp = st.text_input("Course Code (ID)", value=st.session_state.exam_details.get('courseCode'))
        
        c1, c2 = st.columns(2)
        if c1.button("💾 Save Draft"):
            if not new_id_inp: st.error("Course Code Required")
            else:
                data = {
                    'exam_details': st.session_state.exam_details,
                    'sections': st.session_state.sections,
                    'status': 'DRAFT',
                    'author_id': st.session_state.user['id'],
                    'author_name': st.session_state.user['name'],
                    'timestamp': str(datetime.datetime.now())
                }
                db.collection("exams").document(new_id_inp).set(data, merge=True)
                st.session_state.current_doc_id = new_id_inp
                st.success("Draft Saved!")

        if c2.button("🚀 Submit for Scrutiny", type="primary"):
            if check_submission_window():
                 db.collection("exams").document(new_id_inp).update({'status': 'SUBMITTED'})
                 st.success("Submitted successfully!")
            else:
                st.error("Submission Window Closed!")

    # 2. SCRUTINIZER CONTROLS
    elif role == 'scrutinizer' and status == 'SUBMITTED':
        comments = st.text_area("Revision Comments (if rejecting)")
        c1, c2 = st.columns(2)
        if c1.button("↩️ Return for Revision"):
            db.collection("exams").document(doc_id).update({'status': 'REVISION', 'scrutiny_comments': comments})
            st.warning("Returned to Faculty")
        
        if c2.button("✅ Approve & Forward", type="primary"):
             db.collection("exams").document(doc_id).update({
                 'status': 'SCRUTINIZED', 
                 'exam_details.scrutinizedBy': st.session_state.user['name']
             })
             st.success("Forwarded to Head")

    # 3. APPROVER CONTROLS
    elif role == 'approver' and status == 'SCRUTINIZED':
        if st.button("🏆 Final Approval (Lock)", type="primary"):
            db.collection("exams").document(doc_id).update({
                'status': 'APPROVED',
                'exam_details.approvedBy': st.session_state.user['name']
            })
            st.balloons()
            st.success("Exam Finalized!")
