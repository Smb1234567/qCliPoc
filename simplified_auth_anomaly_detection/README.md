# Simplified AI-Based Anomaly Detection System for Authentication Logs

This system detects suspicious user access patterns from authentication/authorization logs using statistical analysis and machine learning.

## Features
- **Log ingestion and processing** - Support for multiple log formats (syslog, JSON, CSV, Apache)
- **User behavior profiling** - Comprehensive behavioral baselines for each user
- **Statistical and ML-based anomaly detection** - Combines statistical methods with Isolation Forest
- **Risk scoring and alerting** - Generates alerts with severity levels
- **Dashboard visualization** - Interactive dashboard with detailed analytics

## Setup
```bash
pip install -r requirements.txt
python app.py
```

## Usage

### Basic Usage
1. Place authentication logs in the root directory
2. Run the system: `python app.py --log-file /path/to/logs.log`
3. Access the dashboard at `http://localhost:8050`

### With Demo Data
```bash
python app.py --demo
```

### Dashboard Mode
```bash
python app.py --dashboard
```

## Core Components

### 1. Log Ingestor
- Parses various log formats (syslog, JSON, CSV, Apache)
- Extracts relevant information: timestamps, usernames, IP addresses, event types

### 2. Behavior Profiler
- Builds baseline behavior profiles for each user
- Tracks login times, preferred days, common locations, and login patterns

### 3. Anomaly Detector
- Statistical detection: flags unusual login times, locations, and rapid failed attempts
- ML detection: uses Isolation Forest to identify anomalous patterns

### 4. Alert System
- Generates alerts with risk scores (low, medium, high)
- Stores alerts in SQLite database
- Logs alerts to file for audit trail

### 5. Dashboard
- Visualizes alert trends over time
- Shows severity distribution
- Displays top users with anomalies
- Lists recent alerts in a table

## Output
- Processed logs saved as CSV files (e.g., `processed_logs_YYYYMMDD_HHMMSS.csv`)
- User profiles saved as pickle files (e.g., `profiles_YYYYMMDD_HHMMSS.pkl`)
- Alerts stored in `alert_history.db` and logged to `alerts.log`