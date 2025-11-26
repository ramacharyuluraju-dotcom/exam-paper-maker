import streamlit as st
import datetime

# --- Page Configuration ---
st.set_page_config(
    page_title="AMC Exam Maker",
    page_icon="📄",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- State Management (Initialize Data) ---
if 'exam_details' not in st.session_state:
    st.session_state.exam_details = {
        'instituteName': 'AMC ENGINEERING COLLEGE',
        'subHeader': '(AUTONOMOUS)',
        'accreditation': 'NAAC A+ | NBA Accredited',
        'affiliation': 'Affiliated to VTU & AICTE',
        'department': 'Department of Electronics & Communication Engineering',
        'examName': 'Internal Assessment – 1',
        'semester': '1st Semester B.E – November 2025',
        'courseName': 'Introduction To Electronics & Communication',
        'courseCode': '1BESC104C',
        'maxMarks': '50',
        'duration': '90 mins',
        'preparedBy': 'Anupama T',
        'scrutinizedBy': '',
        'approvedBy': ''
    }

if 'sections' not in st.session_state:
    st.session_state.sections = [
        {
            'id': 1,
            'isNote': False,
            'questions': [
                {'id': 101, 'qNo': '1. a', 'text': 'Demonstrate the process of converting an alternating current (AC) supply into a direct current (DC) output, using a block diagram and illustrate with waveforms at each essential stage', 'marks': '7', 'co': '3', 'level': '2'},
                {'id': 102, 'qNo': 'b', 'text': 'Illustrate how a single diode and a capacitor function together to convert an AC input into a DC voltage with residual ripple, with the circuit diagram and relevant waveforms.', 'marks': '7', 'co': '3', 'level': '2'},
                {'id': 103, 'qNo': 'c', 'text': 'Explain operation of a voltage doubler circuit', 'marks': '6', 'co': '1', 'level': '1'},
                {'id': 104, 'qNo': '', 'text': 'OR', 'marks': '', 'co': '', 'level': ''},
                {'id': 105, 'qNo': '2. a', 'text': 'The L-C smoothing filter in a 60 Hz mains operated half-wave rectifier circuit consists of an inductor, L of 5H and a capacitor, C1 of 200µF. If 4V of ripple appears at the input of the circuit, determine the amount of ripple appearing at the output.', 'marks': '7', 'co': '3', 'level': '3'},
                {'id': 106, 'qNo': 'b', 'text': 'Propose a solution for improving the stability in the output voltage coming from a smoothing filter.', 'marks': '7', 'co': '3', 'level': '2'},
                {'id': 107, 'qNo': 'c', 'text': 'Describe the current control mechanism in an NPN transistor', 'marks': '6', 'co': '1', 'level': '1'},
            ]
        },
        {
            'id': 2,
            'isNote': True,
            'text': 'Note: Answer three full questions selecting one from each module'
        },
        {
            'id': 3,
            'isNote': False,
            'questions': [
                {'id': 301, 'qNo': '3. a', 'text': 'Derive the loop gain expression for a typical oscillator circuit, and state the necessary conditions for achieving sustained oscillations.', 'marks': '8', 'co': '1', 'level': '2'},
                {'id': 302, 'qNo': 'b', 'text': 'An operational amplifier operating with negative feedback produces an output voltage of 12 V when supplied with an input of 250 mV. Determine the value of the closed-loop voltage gain in db.', 'marks': '4', 'co': '3', 'level': '3'}
            ]
        }
    ]

# --- Helper Functions ---
def add_section(is_note=False):
    new_id = int(datetime.datetime.now().timestamp() * 1000)
    if is_note:
        st.session_state.sections.append({'id': new_id, 'isNote': True, 'text': 'Note: '})
    else:
        st.session_state.sections.append({
            'id': new_id, 
            'isNote': False, 
            'questions': [{'id': new_id + 1, 'qNo': '', 'text': '', 'marks': '', 'co': '', 'level': ''}]
        })

def delete_section(index):
    st.session_state.sections.pop(index)

def add_question(section_index):
    new_id = int(datetime.datetime.now().timestamp() * 1000)
    st.session_state.sections[section_index]['questions'].append({
        'id': new_id, 'qNo': '', 'text': '', 'marks': '', 'co': '', 'level': ''
    })

def delete_question(section_index, question_index):
    st.session_state.sections[section_index]['questions'].pop(question_index)

# --- Sidebar Editor ---
with st.sidebar:
    st.title("📝 Exam Editor")
    
    with st.expander("🏫 Header Details", expanded=False):
        st.session_state.exam_details['instituteName'] = st.text_input("Institute Name", st.session_state.exam_details['instituteName'])
        st.session_state.exam_details['subHeader'] = st.text_input("Sub Header", st.session_state.exam_details['subHeader'])
        st.session_state.exam_details['accreditation'] = st.text_input("Accreditation", st.session_state.exam_details['accreditation'])
        st.session_state.exam_details['affiliation'] = st.text_input("Affiliation", st.session_state.exam_details['affiliation'])
        st.session_state.exam_details['department'] = st.text_input("Department", st.session_state.exam_details['department'])
        st.session_state.exam_details['examName'] = st.text_input("Exam Name", st.session_state.exam_details['examName'])
        st.session_state.exam_details['semester'] = st.text_input("Semester/Date", st.session_state.exam_details['semester'])

    with st.expander("📚 Course Details", expanded=False):
        c1, c2 = st.columns(2)
        st.session_state.exam_details['courseName'] = c1.text_input("Course Name", st.session_state.exam_details['courseName'])
        st.session_state.exam_details['maxMarks'] = c2.text_input("Max Marks", st.session_state.exam_details['maxMarks'])
        st.session_state.exam_details['courseCode'] = c1.text_input("Course Code", st.session_state.exam_details['courseCode'])
        st.session_state.exam_details['duration'] = c2.text_input("Duration", st.session_state.exam_details['duration'])

    with st.expander("✍️ Signatories", expanded=False):
        st.session_state.exam_details['preparedBy'] = st.text_input("Prepared By", st.session_state.exam_details['preparedBy'])
        st.session_state.exam_details['scrutinizedBy'] = st.text_input("Scrutinized By", st.session_state.exam_details['scrutinizedBy'])
        st.session_state.exam_details['approvedBy'] = st.text_input("Approved By", st.session_state.exam_details['approvedBy'])

    st.markdown("---")
    st.subheader("Questions")

    # Iterate over sections
    for i, section in enumerate(st.session_state.sections):
        with st.expander(f"Block {i+1} ({'Note' if section.get('isNote') else 'Questions'})", expanded=True):
            
            # Delete Section Button
            if st.button("Delete Block", key=f"del_sec_{section['id']}"):
                delete_section(i)
                st.rerun()

            if section.get('isNote'):
                # Note Editor
                section['text'] = st.text_input("Instruction Text", section['text'], key=f"note_{section['id']}")
            else:
                # Questions Editor
                for j, q in enumerate(section['questions']):
                    st.markdown(f"**Q{j+1}**")
                    c1, c2 = st.columns([1, 4])
                    q['qNo'] = c1.text_input("No.", q['qNo'], key=f"qno_{q['id']}")
                    q['text'] = c2.text_area("Text (Type 'OR' for divider)", q['text'], key=f"txt_{q['id']}", height=68)
                    
                    if q['text'].strip().upper() != 'OR':
                        c3, c4, c5 = st.columns(3)
                        q['marks'] = c3.text_input("Marks", q['marks'], key=f"mrk_{q['id']}")
                        q['co'] = c4.text_input("CO", q['co'], key=f"co_{q['id']}")
                        q['level'] = c5.text_input("Lvl", q['level'], key=f"lvl_{q['id']}")
                    
                    if st.button("🗑️ Remove Q", key=f"del_q_{q['id']}"):
                        delete_question(i, j)
                        st.rerun()
                    st.divider()
                
                if st.button("➕ Add Question", key=f"add_q_{section['id']}"):
                    add_question(i)
                    st.rerun()

    c1, c2 = st.columns(2)
    if c1.button("Add Question Block"):
        add_section(False)
        st.rerun()
    if c2.button("Add Note/Instruction"):
        add_section(True)
        st.rerun()

# --- Main Preview Area (HTML Generation) ---

def generate_html(details, sections):
    # Construct rows for the HTML table
    table_rows = ""
    for section in sections:
        if section.get('isNote'):
            table_rows += f"""
            <tr style="border-bottom: 1px solid black;">
                <td colspan="5" style="padding: 8px; font-weight: bold; font-size: 14px;">
                    {section['text']}
                </td>
            </tr>
            """
        else:
            for q in section['questions']:
                if q['text'].strip().upper() == 'OR':
                    table_rows += """
                    <tr style="border-bottom: 1px solid black;">
                        <td colspan="5" style="padding: 4px; text-align: center; font-weight: bold; font-size: 14px;">
                            OR
                        </td>
                    </tr>
                    """
                else:
                    table_rows += f"""
                    <tr style="border-bottom: 1px solid black; font-size: 14px;">
                        <td style="padding: 8px; border-right: 1px solid black; text-align: center; font-weight: bold; vertical-align: top;">{q['qNo']}</td>
                        <td style="padding: 8px; border-right: 1px solid black; vertical-align: top; text-align: justify;">{q['text']}</td>
                        <td style="padding: 8px; border-right: 1px solid black; text-align: center; vertical-align: top;">{q['marks']}</td>
                        <td style="padding: 8px; border-right: 1px solid black; text-align: center; vertical-align: top;">{q['co']}</td>
                        <td style="padding: 8px; text-align: center; vertical-align: top;">{q['level']}</td>
                    </tr>
                    """

    # Full HTML Document
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Noto+Serif:wght@400;700&family=Open+Sans:wght@400;700;800&display=swap');
            body {{ font-family: 'Noto Serif', serif; color: black; line-height: 1.3; background: white; }}
            .paper-container {{
                width: 210mm;
                min-height: 297mm;
                padding: 15mm;
                margin: 0 auto;
                background: white;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
                position: relative;
            }}
            .header-grid {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }}
            .logo-box {{ width: 90px; height: 90px; border: 1px solid #ccc; display: flex; align-items: center; justify-content: center; background: #f9f9f9; font-family: sans-serif; font-size: 10px; color: #999; }}
            .header-text {{ flex: 1; text-align: center; padding: 0 20px; }}
            .header-title {{ font-family: 'Open Sans', sans-serif; font-size: 24px; font-weight: 800; color: #1e3a8a; margin: 0; letter-spacing: 0.5px; text-transform: uppercase; }}
            .header-sub {{ font-weight: bold; margin: 2px 0; font-size: 14px; }}
            .accreditation {{ display: inline-block; background-color: #fef08a; padding: 2px 8px; border: 1px solid #eab308; border-radius: 4px; font-size: 11px; font-weight: bold; margin: 2px 0; }}
            .affiliation {{ font-size: 11px; font-weight: bold; margin-top: 4px; }}
            
            .usn-row {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
            .usn-boxes {{ display: flex; gap: 4px; }}
            .usn-box {{ width: 22px; height: 22px; border: 1px solid black; }}
            
            .divider {{ width: 100%; height: 1px; background: black; margin: 2px 0; }}
            
            .meta-info {{ text-align: center; font-weight: bold; margin: 15px 0; font-size: 14px; }}
            
            .course-grid {{ width: 100%; margin-bottom: 20px; font-weight: bold; font-size: 14px; }}
            .course-row {{ display: flex; justify-content: space-between; margin-bottom: 4px; }}
            
            table {{ width: 100%; border-collapse: collapse; border: 1px solid black; margin-bottom: 30px; }}
            th {{ border-bottom: 1px solid black; border-right: 1px solid black; padding: 5px; background: white; }}
            th:last-child {{ border-right: none; }}
            
            .footer {{ display: flex; justify-content: space-between; margin-top: 50px; padding-top: 20px; }}
            .sig-block {{ width: 30%; text-align: center; }}
            .sig-line {{ font-size: 10px; color: #999; font-weight: bold; margin-bottom: 10px; }}
            .sig-title {{ font-weight: bold; font-size: 14px; }}
            .sig-sub {{ font-size: 12px; }}
            .sig-name {{ margin-top: 5px; font-weight: bold; font-size: 14px; }}

            @media print {{
                body {{ background: white; margin: 0; padding: 0; -webkit-print-color-adjust: exact; }}
                .paper-container {{ box-shadow: none; margin: 0; width: 100%; padding: 0; }}
                .logo-box {{ border: none; }} /* Hide logo border in print if needed */
                .accreditation {{ background-color: transparent; border: 1px solid black; }}
                .stApp {{ display: none; }} /* Try to hide streamlit UI */
            }}
        </style>
    </head>
    <body>
        <div class="paper-container">
            <div class="header-grid">
                <div class="logo-box">AMC Logo</div>
                <div class="header-text">
                    <h1 class="header-title">{details['instituteName']}</h1>
                    <div class="header-sub">{details['subHeader']}</div>
                    <div class="accreditation">{details['accreditation']}</div>
                    <div class="affiliation">{details['affiliation']}</div>
                </div>
            </div>

            <div class="usn-row">
                <span style="font-weight: bold;">USN</span>
                <div class="usn-boxes">
                    {"".join(['<div class="usn-box"></div>' for _ in range(10)])}
                </div>
            </div>

            <div class="divider"></div>
            <div class="divider" style="margin-bottom: 15px;"></div>

            <div class="meta-info">
                <div>{details['department']}</div>
                <div>{details['examName']}</div>
                <div>{details['semester']}</div>
            </div>

            <div class="course-grid">
                <div class="course-row">
                    <span>Course Name: {details['courseName']}</span>
                    <span>Max Marks: {details['maxMarks']}</span>
                </div>
                <div class="course-row">
                    <span>Course Code: {details['courseCode']}</span>
                    <span>Time: {details['duration']}</span>
                </div>
            </div>

            <table>
                <thead>
                    <tr style="text-align: center; font-weight: bold;">
                        <th style="width: 10%;">Q.No</th>
                        <th style="width: 60%;">Question</th>
                        <th style="width: 10%;">Marks</th>
                        <th style="width: 10%;">COs</th>
                        <th style="width: 10%;">Level</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>

            <div class="footer">
                <div class="sig-block">
                    <div class="sig-line">Signature</div>
                    <div class="sig-title">Prepared by</div>
                    <div class="sig-sub">Course Teacher/Coordinator</div>
                    <div class="sig-name">{details['preparedBy']}</div>
                </div>
                <div class="sig-block">
                    <div class="sig-line">Signature</div>
                    <div class="sig-title">Scrutinized by</div>
                    <div class="sig-sub">Module/Program Coordinator</div>
                    <div class="sig-name">{details['scrutinizedBy']}</div>
                </div>
                <div class="sig-block">
                    <div class="sig-line">Signature</div>
                    <div class="sig-title">Approved by</div>
                    <div class="sig-sub">Academic Advisor/PAC</div>
                    <div class="sig-name">{details['approvedBy']}</div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return html_content

# --- Main Page Layout ---
st.markdown("## 📄 Live Preview")

html_code = generate_html(st.session_state.exam_details, st.session_state.sections)

# Render HTML in the app
st.components.v1.html(html_code, height=1100, scrolling=True)

# --- Download Button for Printing ---
st.sidebar.markdown("---")
st.sidebar.download_button(
    label="🖨️ Download Print-Ready HTML",
    data=html_code,
    file_name="amc_question_paper.html",
    mime="text/html",
    help="Download this file and open it in your browser to print (Ctrl+P)."
)