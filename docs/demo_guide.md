# AI-Based Anomaly Detection System Demo

This document provides a walkthrough of the AI-based anomaly detection system for authentication logs.

## System Components

The system consists of five main components:

1. **Log Ingestor**: Parses and normalizes authentication logs
2. **Behavior Profiler**: Creates user behavior baselines
3. **Anomaly Detector**: Identifies suspicious activities
4. **Alert System**: Generates and manages security alerts
5. **Dashboard**: Visualizes results and system status

## Running the Demo

### Step 1: Install Dependencies

First, install the required packages:

```bash
pip install -r requirements.txt
```

### Step 2: Run the Demo

Execute the demo to see the system in action:

```bash
python app.py --demo
```

### Step 3: View the Dashboard

Start the dashboard to visualize the results:

```bash
python app.py --dashboard
```

Then navigate to `http://localhost:8050` in your browser.

## Demo Walkthrough

### Authentication Log Processing

The demo simulates a week's worth of authentication logs with both normal and anomalous activities:

- Normal user behaviors (regular login times, common locations)
- Anomalous activities (unusual login times, new IP addresses, high-frequency logins)

### Behavior Profiling

For each user, the system tracks:

- Preferred login times (hour of day)
- Common login days (day of week)
- Frequent locations (IP addresses)
- Session durations
- Login success rates

### Anomaly Detection

The system employs multiple detection strategies:

1. **Statistical Analysis**:
   - Unusual login frequency compared to historical patterns
   - Logins at atypical hours for each user
   - Access from new or rare IP addresses

2. **Machine Learning**:
   - Isolation Forest algorithm to identify multivariate outliers
   - Feature engineering combining temporal, user, and location data

### Alert Generation

When anomalies are detected, the system generates alerts with:

- Severity level (High, Medium, Low)
- Explanation of why the activity is considered anomalous
- Timestamp and user information
- Recommended actions

## Dashboard Features

The dashboard provides four main views:

### Overview Tab
- Daily anomaly counts over time
- Distribution of anomaly severities
- Key system metrics

### Anomalies Tab
- Timeline view of detected anomalies
- Detailed table of anomaly information
- Filtering by severity or type

### Users Tab
- Risk scores for each user
- Behavioral patterns and deviations
- Common access locations and times

### Alerts Tab
- Chronological view of generated alerts
- Alert details and severity classification
- Notification status

## Technical Implementation

### Log Parsing
The system supports multiple log formats:
- Syslog format (common in Unix/Linux systems)
- JSON format (used by many modern applications)
- CSV format (structured logs)
- Apache Common/Combined formats

### Feature Engineering
For ML-based detection, the system creates features from raw log data:
- Temporal features (hour, day of week, month)
- Categorical features (user ID, IP address)
- Interaction features (hour-user combinations)

### Model Training
The Isolation Forest model learns normal behavior patterns from historical data and identifies outliers that represent potential security threats.

## Customization

The system can be customized by:

- Adjusting sensitivity thresholds in the configuration
- Adding new log formats to the parser
- Modifying alert templates
- Extending the dashboard with additional visualizations

## Conclusion

This AI-based anomaly detection system provides a comprehensive solution for identifying suspicious activities in authentication logs. By combining statistical methods with machine learning, it offers robust detection capabilities while maintaining interpretability for security analysts.