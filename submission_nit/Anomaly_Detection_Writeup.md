# AI-Powered Anomaly Detection for Authentication Logs

**Student Name:** [Your Name]
**Submission Date:** January 24, 2026
**Subject:** Bootcamp Capstone Project - Problem Statement 1

---

## 1. Problem Summary and Motivation
In the modern cybersecurity landscape, traditional firewalls and rule-based intrusion detection systems (IDS) are no longer sufficient. One of the biggest challenges we face is the "Insider Threat" or the compromised account scenario. If an attacker manages to steal valid credentials (username and password), they can bypass standard authentication checks completely. To the system, they look like a legitimate user.

This project addresses that specific gap. My goal was to build an intelligent "safety net" that sits behind the login screen. By analyzing *patterns* of behavior rather than just checking passwords, we can identify when a valid user account is acting suspiciously. For example, if 'User A' always logs in from New York at 9 AM, and suddenly logs in from Moscow at 3 AM, that is an anomaly. Building a system to detect these outliers automatically—without writing thousands of hard-coded rules—was the core challenge of this assignment.

## 2. System Architecture
I designed the solution as a modular data pipeline using Python. I wanted to ensure that each stage of the process was distinct, making it easier to debug and improve. The architecture flows as follows:

1.  **Log Ingestion**: The system reads raw, unstructured text files (simulating Linux Syslogs).
2.  **Parsing & Cleaning**: A regex-based parser converts the text into structured data (Timestamp, Username, Source IP, Event Type).
3.  **Behavioral Profiling**: This is the "memory" of the system. It builds a history for each user.
4.  **Feature Engineering**: The raw data is converted into numerical vectors suitable for Machine Learning.
5.  **Anomaly Detection (ML)**: An Isolation Forest algorithm analyzes the vectors to find outliers.
6.  **Risk Scoring & Alerting**: The raw model output is translated into human-readable alerts (High/Medium/Low).
7.  **Dashboard**: A visualization layer for analysts to investigate the findings.

## 3. Log Processing
The first hurdle was dealing with the raw data. Authentication logs are messy. I worked with standard `sshd` style logs. I used Python's `re` module to write regular expressions that could extract:
*   **Timestamps**: Converting strings like "Jan 15 10:30:15" into actual Python `datetime` objects was crucial for calculating time differences.
*   **Usernames**: Identifying who is trying to log in.
*   **IP Addresses**: Extracting the source IP.
*   **Outcomes**: Distinguishing between "Accepted password" (Success) and "Failed password" (Failure).

I stored this processed data in a Pandas DataFrame. Using Pandas made it much easier to perform operations like "group by user" or "sort by time" during the feature engineering phase.

## 4. Feature Engineering
This was the most intellectually interesting part of the project. I learned that you can't just feed "IP Address: 192.168.1.1" into a math model. I had to create *derived features* that represent behavior. I focused on five key metrics:

*   **Hour of Day (0-23)**: To capture circadian rhythms. Most users have a set work schedule.
*   **Day of Week (0-6)**: To differentiate between workday and weekend activity.
*   **Login Frequency**: I calculated how many attempts a user made in the last rolling 24-hour window. A sudden spike here usually indicates a brute-force attack.
*   **"New IP" Flag**: By keeping a history of every IP a user has ever used, I created a simple boolean flag (0 or 1). If a user logs in from an IP they have *never* used before, this flag is set to 1.
*   **User Encoding**: I used a numerical encoder for usernames so the model could learn distinct patterns for "admin" vs. "guest".

## 5. Machine Learning Approach
For the core detection engine, I chose an unsupervised learning approach. In a real-world scenario, we rarely have a clean, labeled dataset of "Attacks" vs. "Normal" traffic. We mostly have normal traffic with a few unknown attacks hidden inside.

I utilized the **Isolation Forest** algorithm from the Scikit-Learn library.
*   **Why Isolation Forest?** Unlike other methods that try to profile what "normal" looks like (like Gaussian Mixture Models), Isolation Forest explicitly tries to isolate anomalies. It assumes that anomalies are "few and different."
*   **Implementation**: I trained the model on the entire feature set. The algorithm builds random decision trees. Data points that are easy to isolate (requiring fewer splits in the tree) are scored as anomalies.
*   **Output**: The model returns an "anomaly score." I found that negative scores typically indicated a deviation from the cluster of normal user behavior.

## 6. Risk Scoring and Alerting Logic
The raw score from the ML model is a bit abstract (e.g., -0.654), so I added a logic layer to translate this into actionable intelligence for a security analyst.

*   **CRITICAL / HIGH Risk**: Triggered if the ML Score is extremely low OR if there is a massive spike in failed login attempts (indicating a brute-force attack).
*   **MEDIUM Risk**: Triggered if the user is coming from a "New IP" or an "Unusual Time", even if the password was correct. This might indicate a stolen credential.
*   **LOW Risk**: Minor deviations that are just on the edge of the model's threshold.

I implemented an `AlertManager` class that acts as a gatekeeper. It saves these alerts to a SQLite database (`alert_history.db`) to simulate a persistent audit trail.

## 7. Dashboard Visualization
To make the project "showable," I built a simple web dashboard using **Dash** and **Plotly**. It provides three views:
1.  **Attack Timeline**: A scatter plot where the X-axis is Time and the Y-axis is User. Anomalies are highlighted in red. This makes it instantly obvious if a specific time of day is seeing a spike in attacks.
2.  **Top Risky Users**: A bar chart showing which users have generated the most alerts.
3.  **Alert Feed**: A raw table of the most recent alerts, explaining *why* they triggered (e.g., "Reason: Unusual Time").

## 8. Proof of Concept & Results
I tested the system using a synthetic log file (`auth_logs.txt`) that contained normal traffic mixed with simulated attacks.
*   **Scenario A (The Traveler)**: I simulated a user 'alice' logging in from a new IP range. The system correctly flagged this as a Medium risk anomaly due to the "New IP" feature.
*   **Scenario B (The Hacker)**: I simulated a user 'hacker' trying 10 different passwords in 1 minute. The Frequency feature spiked, and the model correctly identified this as a High-risk anomaly.

## 9. Limitations and Reflections
While I'm proud of this PoC, I learned there are significant limitations:
*   **The "Cold Start" Problem**: When a new employee joins, the system has no history for them. Every login they make looks like an anomaly (New IP, New Time) until the model learns their pattern.
*   **False Positives**: Legitimate users often travel or work late. My current model is a bit too sensitive to these changes.
*   **Static Training**: Currently, I train the model once on a batch of logs. In a real production environment, the model would need to be retrained nightly to adapt to changing user habits.

## 10. Future Improvements
If I had more time to work on this, I would add:
*   **Geo-Location Intelligence**: Instead of just checking the raw IP, I would use a GeoIP database to check the *physical distance*. Logging in from a coffee shop 5 miles away is fine; logging in from a different continent 5 minutes later is physically impossible ("Impossible Travel").
*   **Deep Learning (LSTM)**: I would like to try Recurrent Neural Networks to learn *sequences*. For example, identifying that "User A usually checks email, then logs off" is normal, but "User A checks email, then downloads the entire database" is anomalous.
*   **Feedback Loop**: I would add a button on the dashboard for analysts to mark "False Positive." I could use this data to fine-tune the model over time.

---
*End of Write-up*
