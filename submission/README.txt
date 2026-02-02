README - AI-Powered Anomaly Detection for Authentication Logs
================================================================

1. PROJECT OVERVIEW
-------------------
This project implements an AI-powered system to detect suspicious user access
patterns from authentication logs. It processes logs, profiles user behavior,
uses Machine Learning (Isolation Forest) to detect anomalies, and triggers
alerts for high-risk activities.

2. INSTALLATION
---------------
Prerequisites: Python 3.8+

Install the required packages:
   pip install -r requirements.txt

(Note: requirements.txt is included in the src/ directory or root)

3. HOW TO RUN
-------------
You can run the individual components of the pipeline as follows:

1) Parse Logs:
   python parser.py
   - Reads 'auth_logs.txt'
   - outputs 'parsed_logs.csv'

2) Extract Features:
   python features.py
   - Reads 'parsed_logs.csv'
   - Displays user profiles and feature vectors.

3) Train Model & Detect:
   python model.py
   - Trains the Isolation Forest model.
   - Outputs detected anomalies and scores.

4) Generate Alerts:
   python alerts.py
   - Processes anomalies and simulates sending alerts.
   - Saves alerts to 'alert_history.db' and 'alerts.log'.

5) Dashboard (Optional):
   python dashboard/app.py
   - Starts a web interface at http://localhost:8050

4. FILE DESCRIPTIONS
--------------------
- auth_logs.txt: Sample authentication logs (Syslog format).
- parser.py: Log parsing script.
- features.py: Feature engineering and profiling demonstration.
- model.py: Machine learning model training and detection.
- alerts.py: Alert generation logic.
- src/: Source code modules (LogIngestor, BehaviorProfiler, AnomalyDetector, AlertSystem).
- dashboard/: Source code for the Dash web application.

5. OUTPUT
---------
The system outputs:
- Console: Step-by-step progress and detection results.
- parsed_logs.csv: Structured log data.
- alerts.log: Log file containing generated security alerts.
- alert_history.db: SQLite database storing alert history.
