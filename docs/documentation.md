# AI-Based Anomaly Detection System for Authentication Logs

## Project Overview

This system implements an AI-based anomaly detection solution for identifying suspicious user access patterns from authentication/authorization logs. The system combines statistical analysis and machine learning techniques to detect unusual activities that may indicate security threats.

## Architecture

The system consists of five main components:

### 1. Log Ingestion Module (`src/log_ingestor.py`)
- Parses various log formats (syslog, JSON, CSV, Apache)
- Converts logs to a standardized format
- Handles multiple log sources and file types

### 2. Behavior Profiling System (`src/behavior_profiler.py`)
- Creates baseline behavior profiles for each user
- Tracks login patterns (time of day, day of week, location)
- Monitors session duration and success rates
- Updates profiles dynamically as new data arrives

### 3. Anomaly Detection Algorithms (`src/anomaly_detector.py`)
- Statistical methods for detecting unusual patterns
- Machine learning models (Isolation Forest) for anomaly detection
- Multiple detection strategies combined for comprehensive coverage

### 4. Alerting System (`src/alert_system.py`)
- Generates alerts based on detected anomalies
- Configurable severity levels and thresholds
- Multiple notification channels (email, log)
- Alert history tracking and reporting

### 5. Dashboard Interface (`dashboard/app.py`)
- Real-time visualization of detected anomalies
- User behavior profiling insights
- Alert monitoring and management
- Interactive charts and graphs

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd auth_anomaly_detection
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage
Process authentication logs and detect anomalies:
```bash
python app.py --log-file /path/to/auth.log
```

Process all logs in a directory:
```bash
python app.py --log-dir /path/to/log/directory
```

Specify log format:
```bash
python app.py --log-file auth.log --format syslog
```

### Run Demo
Run a demonstration with sample data:
```bash
python app.py --demo
```

### Start Dashboard
Launch the web-based dashboard:
```bash
python app.py --dashboard
```

Access the dashboard at `http://localhost:8050`

### Advanced Options
```bash
python app.py --log-file auth.log --format json --dashboard
```

## Configuration

The system can be configured using `config.json`:

```json
{
  "email_settings": {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "sender_email": "your-email@gmail.com",
    "sender_password": "your-app-password",
    "recipient_emails": ["admin@company.com", "security@company.com"]
  },
  "alert_thresholds": {
    "high_severity_count": 3,
    "medium_severity_count": 5,
    "time_window_minutes": 60
  },
  "notification_channels": ["email", "log"],
  "alert_templates": {
    "high_severity": "HIGH SEVERITY ALERT: Suspicious activity detected for user {username}",
    "medium_severity": "MEDIUM SEVERITY: Unusual activity detected for user {username}",
    "low_severity": "LOW SEVERITY: Minor anomaly detected for user {username}"
  }
}
```

## Anomaly Detection Methods

### Statistical Detection
- **Frequency Analysis**: Identifies unusually high login frequencies
- **Time Pattern Analysis**: Detects logins at unusual times
- **Location Analysis**: Flags logins from new or unusual locations

### Machine Learning Detection
- **Isolation Forest**: Identifies outliers in multidimensional feature space
- **Feature Engineering**: Combines temporal, user, and IP-based features
- **Continuous Learning**: Updates models as new data arrives

## Alert Levels

- **High Severity**: Immediate attention required (e.g., login from new country at unusual time)
- **Medium Severity**: Monitor and investigate (e.g., unusual login time)
- **Low Severity**: Minor anomalies for awareness (e.g., slight increase in login frequency)

## Data Flow

1. **Log Ingestion**: Raw logs are parsed and normalized
2. **Behavior Modeling**: User profiles are created and updated
3. **Anomaly Detection**: Both statistical and ML methods detect anomalies
4. **Alert Generation**: Relevant alerts are created based on severity
5. **Visualization**: Results are displayed in the dashboard

## Dashboard Features

- **Overview Tab**: System health and summary statistics
- **Anomalies Tab**: Detailed view of detected anomalies
- **Users Tab**: Individual user behavior profiles and risk scores
- **Alerts Tab**: Generated alerts with details and timeline
- **Settings Tab**: Configuration options for detection parameters

## Sample Output

When running the system, you'll see output like:

```
Initializing AI Anomaly Detection System...
Processing authentication logs...
Loaded 1500 log entries
Creating user behavior profiles...
Created profiles for 45 users
Detecting anomalies...
Detected 23 anomalies
Generating alerts...
Created 23 alerts

--- Detection Summary ---
Total log entries processed: 1500
Unique users: 45
Anomalies detected: 23
Anomalies by severity:
  High: 5
  Medium: 12
  Low: 6

Alerts generated: 23
Results saved to processed_logs_20230115_103045.csv and profiles_20230115_103045.pkl
```

## Extending the System

The modular design allows for easy extension:

- Add new log format parsers to `LogIngestor`
- Implement additional anomaly detection algorithms in `AnomalyDetector`
- Create new visualization components in the dashboard
- Add notification channels to `AlertSystem`

## Security Considerations

- Store email credentials securely, not in plain text
- Regularly rotate API keys and passwords
- Monitor the system for signs of compromise
- Encrypt sensitive log data at rest

## Performance Notes

- The system processes logs efficiently using pandas DataFrames
- Machine learning models are optimized for speed
- Database queries are indexed for quick retrieval
- Memory usage scales with the number of users being monitored

## Troubleshooting

- If the dashboard doesn't start, ensure all dependencies are installed
- Check logs in `alerts.log` for system errors
- Verify that the log format matches the specified format option
- Ensure sufficient disk space for profile storage