# AI-Powered Anomaly Detection for Authentication Logs

## Problem Summary
In today's cybersecurity landscape, compromised credentials are a leading cause of data breaches. Traditional rule-based systems often fail to detect sophisticated attacks where attackers use valid credentials but exhibit abnormal behavior. Detecting abnormal logins—such as those at unusual times, from new locations, or with unusual frequency—is critical for identifying account takeovers and insider threats before significant damage occurs. This project aims to build an automated, AI-driven system to identify these anomalies in authentication logs with high precision.

## System Architecture
The system follows a modular data processing pipeline:

**Log Source** (Raw Text) → **Parser** (Structured Data) → **Feature Extraction** (Numeric Vectors) → **ML Model** (Isolation Forest) → **Risk Score** (Anomaly Score) → **Alerts** (Notifications) → **Dashboard** (Visualization)

1.  **Log Source**: Raw authentication logs (e.g., Syslog, SSH logs).
2.  **Parser**: Converts raw text into structured fields (Timestamp, User, IP, Event Type).
3.  **Feature Extraction**: specific metrics are derived to represent user behavior.
4.  **ML Model**: An unsupervised model learns "normal" patterns and flags deviations.
5.  **Risk Score**: Model outputs are mapped to risk levels (Low, Medium, High).
6.  **Alerts**: High-risk events trigger notifications.
7.  **Dashboard**: A web interface allows analysts to review and investigate alerts.

## Log Processing
Logs are ingested from text files (e.g., `auth_logs.txt`). A regex-based parser (`LogIngestor`) extracts key information:
-   **Timestamp**: Converted to a standard datetime object.
-   **Username**: The account attempting access.
-   **IP Address**: The source of the connection.
-   **Event Type**: e.g., 'Failed password', 'Accepted password', 'Disconnected'.
The parsed data is stored in a Pandas DataFrame for efficient manipulation.

## Feature Engineering
To enable machine learning, we convert raw logs into numeric features (`BehaviorProfiler` & `AnomalyDetector`):
-   **Time Features**: Hour of day, Day of week.
-   **Frequency**: Number of logins in the last 24 hours.
-   **Location**: Boolean flags for "New IP Address" (compared to user history).
-   **User Encoding**: Numerical encoding of usernames to track user-specific patterns.
-   **Interaction Features**: Hour × User interactions (to capture "User X usually logs in at Hour Y").

## Machine Learning Model
We utilize **Isolation Forest**, an unsupervised anomaly detection algorithm.
-   **Why Isolation Forest?** It is effective for high-dimensional data and does not require labeled "attack" data (which is often scarce). It works by randomly selecting a feature and a split value to isolate observations. Anomalies are "few and different," so they are isolated in fewer steps than normal points.
-   **Training**: The model is trained on the historical feature set.
-   **Output**: It produces an "anomaly score". Lower scores (typically negative in Scikit-Learn's implementation) indicate higher abnormality.

## Risk Scoring Logic
The raw anomaly scores from the Isolation Forest and statistical thresholds are mapped to severity levels:
-   **High Risk**: Model score < -0.5 OR High frequency deviation (> 3 sigma).
-   **Medium Risk**: Model score < 0 OR New IP Address / Unusual Time.
-   **Low Risk**: Minor deviations (e.g., slightly unusual time).

## Alert System
The `AlertSystem` processes the scored events.
-   **Trigger**: Alerts are triggered when an anomaly's severity is 'High' or 'Medium'.
-   **Deduplication**: Repeated alerts for the same event are suppressed.
-   **Storage**: Alerts are saved to `alert_history.db` (SQLite) and `alerts.log`.
-   **Notification**: The system supports email notifications for High-severity alerts.

## Dashboard
A **Dash (Plotly)** web application provides a visual interface (`app.py`):
-   **Overview**: Summary stats of total anomalies and severity distribution.
-   **Anomaly Timeline**: A scatter plot showing when anomalies occurred and which user was involved.
-   **Details**: A tabular view explaining *why* an alert was raised (e.g., "Login at 3 AM, unusual for this user").

## Proof of Concept Summary
The implemented PoC successfully parses a sample `auth_logs.txt`, trains the model, and identifies synthetic anomalies (e.g., "hacker" failing passwords, "alice" logging in at unusual times). The Python scripts demonstrate the full pipeline from raw text to a generated alert.

## Limitations
-   **Cold Start**: New users will be flagged as anomalies until a profile is built.
-   **Traveling Users**: Legitimate users changing locations frequently may generate false positives (needs VPN/Geo-IP context).
-   **Static Dataset**: The current PoC trains on a batch; a production system needs continuous online learning.

## Future Improvements
-   **Geo-IP Integration**: Resolve IPs to physical locations to reduce false positives for nearby travel.
-   **Deep Learning**: Implement LSTM (Long Short-Term Memory) networks to model sequential login patterns (e.g., Login -> Access Admin -> Download).
-   **Feedback Loop**: Allow analysts to mark alerts as "False Positive" to retrain the model.
