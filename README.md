\# Universal Log Pre-processing Framework (ULPF)



\### SIH26156 — Smart India Hackathon 2026



ULPF is a modular log pre-processing framework that converts heterogeneous raw logs into a unified, structured and analytics-ready representation while preserving the original event data for traceability.



\## Features



\- Heterogeneous log file ingestion

\- Source-specific log parsing

\- Field extraction and normalization

\- Unified event representation

\- Unmapped and malformed record detection

\- Duplicate detection

\- Unique IP extraction

\- Rule-based anomaly detection

\- Interactive dashboard

\- JSONL export

\- Raw event preservation for traceability



\## MVP Workflow



```text

Log File

&#x20;  ↓

Flask Backend

&#x20;  ↓

Log Parser

&#x20;  ↓

Field Extraction

&#x20;  ↓

Processing \& Validation

&#x20;  ↓

Normalized Events

&#x20;  ↓

Dashboard

&#x20;  ↓

JSONL Export

Technology Stack

Backend: Python, Flask

Log Processing: Python Regex

Frontend: HTML, CSS, JavaScript

Visualization: Chart.js

Output: JSONL



Project Structure

ulpf-mvp/

│

├── app.py

├── log\_parser.py

├── requirements.txt

├── sample\_logs.log

│

├── static/

│   ├── css/

│   │   └── style.css

│   └── js/

│       └── main.js

│

├── templates/

│   └── index.html

│

└── README.md



Running the MVP

1\. Clone the Repository

git clone https://github.com/akash24-hash/ulpf-mvp.git

cd ulpf-mvp

2\. Install Dependencies

pip install -r requirements.txt

3\. Run the Application

python app.py

4\. Open the Dashboard



Open the following URL in your browser:



http://127.0.0.1:5000

5\. Test the Prototype



Upload the included:



sample\_logs.log



click



Process Logs



The dashboard displays:



Total Records

Parsed Records

Unmapped Records

Duplicate Records

Unique IPs

Detected Anomalies

Events Over Time

Top Source IPs

Parse Status

Normalized Events



Processed records can be exported as JSONL.



Current MVP Scope



The current prototype demonstrates the core log preprocessing workflow using representative Apache/web-server, Syslog and application log patterns.



The implemented workflow is:



Ingestion

&#x20;  ↓

Parsing

&#x20;  ↓

Field Extraction

&#x20;  ↓

Normalization

&#x20;  ↓

Validation

&#x20;  ↓

Duplicate Detection

&#x20;  ↓

Rule-Based Anomaly Detection

&#x20;  ↓

Dashboard Visualization

&#x20;  ↓

JSONL Export



Output



The framework generates normalized event records containing fields such as:



Timestamp

Source Type

Source IP

Severity

Action

Event Template

Processing Status



The original raw event is retained for traceability.



Team



CodeForge



Smart India Hackathon 2026



Problem Statement: SIH26156



Project: Universal Log Pre-processing Framework (ULPF)





Then run:



```powershell

git add README.md

git commit -m "Add README documentation"

git push

