import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import sqlite3
from pathlib import Path
import logging


class AlertSystem:
    """
    System for generating and managing alerts based on detected anomalies.
    """
    
    def __init__(self, config_file='config.json'):
        """
        Initialize the alert system with configuration settings.
        
        Args:
            config_file (str): Path to the configuration file
        """
        self.config = self.load_config(config_file)
        self.alert_history_db = 'alert_history.db'
        self.setup_database()
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('alerts.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_config(self, config_file):
        """
        Load configuration from JSON file.
        
        Args:
            config_file (str): Path to the configuration file
        
        Returns:
            dict: Configuration dictionary
        """
        default_config = {
            "email_settings": {
                "smtp_server": "smtp.gmail.com",
                "smtp_port": 587,
                "sender_email": "",
                "sender_password": "",
                "recipient_emails": []
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
        
        try:
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                # Merge with defaults
                for key in default_config:
                    if key in user_config:
                        if isinstance(default_config[key], dict):
                            default_config[key].update(user_config[key])
                        else:
                            default_config[key] = user_config[key]
        except FileNotFoundError:
            # Create default config file if it doesn't exist
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
        
        return default_config
    
    def setup_database(self):
        """
        Set up the SQLite database for storing alert history.
        """
        conn = sqlite3.connect(self.alert_history_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT,
                ip_address TEXT,
                severity TEXT,
                anomaly_type TEXT,
                details TEXT,
                notified BOOLEAN DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_alert_to_db(self, alert):
        """
        Save an alert to the database.

        Args:
            alert (dict): Alert information to save
        """
        conn = sqlite3.connect(self.alert_history_db)
        cursor = conn.cursor()

        # Convert datetime objects to string format for database storage
        timestamp_str = alert['timestamp']
        if hasattr(alert['timestamp'], 'isoformat'):
            timestamp_str = alert['timestamp'].isoformat()

        cursor.execute('''
            INSERT INTO alerts (timestamp, username, ip_address, severity, anomaly_type, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            timestamp_str,
            alert.get('username', ''),
            alert.get('ip_address', ''),
            alert['severity'],
            alert.get('anomaly_type', ''),
            alert.get('details', '')
        ))

        conn.commit()
        conn.close()
    
    def get_recent_alerts(self, minutes=60):
        """
        Get alerts from the specified time window.
        
        Args:
            minutes (int): Number of minutes to look back
        
        Returns:
            list: List of recent alerts
        """
        conn = sqlite3.connect(self.alert_history_db)
        cursor = conn.cursor()
        
        from_time = datetime.now() - timedelta(minutes=minutes)
        
        cursor.execute('''
            SELECT * FROM alerts 
            WHERE timestamp > ? AND notified = 0
            ORDER BY timestamp DESC
        ''', (from_time.isoformat(),))
        
        rows = cursor.fetchall()
        columns = [description[0] for description in cursor.description]
        
        alerts = []
        for row in rows:
            alert = dict(zip(columns, row))
            alerts.append(alert)
        
        conn.close()
        return alerts
    
    def send_email_notification(self, subject, body, recipient_emails=None):
        """
        Send an email notification about an alert.
        
        Args:
            subject (str): Email subject
            body (str): Email body
            recipient_emails (list): List of recipient emails (uses config if None)
        """
        if recipient_emails is None:
            recipient_emails = self.config['email_settings']['recipient_emails']
        
        if not recipient_emails:
            self.logger.warning("No recipient emails configured")
            return
        
        try:
            smtp_server = self.config['email_settings']['smtp_server']
            smtp_port = self.config['email_settings']['smtp_port']
            sender_email = self.config['email_settings']['sender_email']
            sender_password = self.config['email_settings']['sender_password']
            
            if not sender_email or not sender_password:
                self.logger.error("Email credentials not configured properly")
                return
            
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = ', '.join(recipient_emails)
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            
            text = msg.as_string()
            server.sendmail(sender_email, recipient_emails, text)
            server.quit()
            
            self.logger.info(f"Alert email sent to {recipient_emails}")
        
        except Exception as e:
            self.logger.error(f"Failed to send email: {str(e)}")
    
    def generate_alert_message(self, alert):
        """
        Generate a human-readable message for an alert based on its severity.
        
        Args:
            alert (dict): Alert information
        
        Returns:
            str: Formatted alert message
        """
        template = self.config['alert_templates'].get(
            f"{alert['severity']}_severity", 
            "ANOMALY DETECTED: {details}"
        )
        
        return template.format(
            username=alert.get('username', 'Unknown'),
            severity=alert['severity'].upper(),
            details=alert.get('details', 'No details available')
        )
    
    def trigger_alert(self, anomaly):
        """
        Process an anomaly and trigger appropriate alerts.
        
        Args:
            anomaly (dict): Anomaly information
        """
        # Save alert to database
        self.save_alert_to_db(anomaly)
        
        # Generate alert message
        alert_message = self.generate_alert_message(anomaly)
        
        # Log the alert
        self.logger.info(f"Alert triggered: {alert_message}")
        
        # Check if we should send notification based on thresholds
        if self.should_send_notification(anomaly['severity']):
            # Send notifications through configured channels
            self.send_notifications(anomaly, alert_message)
            
            # Mark alerts as notified in DB
            self.mark_alerts_notified(anomaly['severity'])
    
    def should_send_notification(self, severity):
        """
        Determine if a notification should be sent based on thresholds.
        
        Args:
            severity (str): Severity level of the alert
        
        Returns:
            bool: True if notification should be sent
        """
        time_window = self.config['alert_thresholds']['time_window_minutes']
        recent_alerts = self.get_recent_alerts(time_window)
        
        # Count alerts by severity in the time window
        severity_counts = {}
        for alert in recent_alerts:
            sev = alert['severity']
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Check thresholds
        if severity == 'high':
            threshold = self.config['alert_thresholds']['high_severity_count']
            return severity_counts.get('high', 0) >= threshold
        elif severity == 'medium':
            threshold = self.config['alert_thresholds']['medium_severity_count']
            return severity_counts.get('medium', 0) >= threshold
        else:
            # For low severity, always send if it meets criteria
            return True
    
    def send_notifications(self, anomaly, alert_message):
        """
        Send notifications through all configured channels.
        
        Args:
            anomaly (dict): Anomaly information
            alert_message (str): Formatted alert message
        """
        channels = self.config['notification_channels']
        
        if 'email' in channels:
            subject = f"[{anomaly['severity'].upper()}] Security Alert: {anomaly.get('username', 'Unknown User')}"
            body = f"""
Security Alert

Timestamp: {anomaly['timestamp']}
User: {anomaly.get('username', 'Unknown')}
IP Address: {anomaly.get('ip_address', 'Unknown')}
Severity: {anomaly['severity'].upper()}
Type: {anomaly.get('anomaly_type', 'Unknown')}
Details: {anomaly.get('details', 'No details available')}

Automated message from AI Anomaly Detection System
            """
            self.send_email_notification(subject, body)
        
        if 'log' in channels:
            self.logger.warning(f"Security Alert: {alert_message}")
    
    def mark_alerts_notified(self, severity):
        """
        Mark alerts of a certain severity as notified in the database.
        
        Args:
            severity (str): Severity level to mark as notified
        """
        conn = sqlite3.connect(self.alert_history_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE alerts SET notified = 1 
            WHERE severity = ? AND notified = 0
        ''', (severity,))
        
        conn.commit()
        conn.close()
    
    def get_alert_summary(self, days=7):
        """
        Get a summary of alerts for the specified number of days.
        
        Args:
            days (int): Number of days to summarize
        
        Returns:
            dict: Summary of alerts
        """
        conn = sqlite3.connect(self.alert_history_db)
        cursor = conn.cursor()
        
        from_time = datetime.now() - timedelta(days=days)
        
        cursor.execute('''
            SELECT severity, COUNT(*) as count
            FROM alerts 
            WHERE timestamp > ?
            GROUP BY severity
        ''', (from_time.isoformat(),))
        
        rows = cursor.fetchall()
        
        summary = {}
        for severity, count in rows:
            summary[severity] = count
        
        # Also get top users affected
        cursor.execute('''
            SELECT username, COUNT(*) as count
            FROM alerts 
            WHERE timestamp > ? AND username != ''
            GROUP BY username
            ORDER BY count DESC
            LIMIT 10
        ''', (from_time.isoformat(),))
        
        user_rows = cursor.fetchall()
        summary['top_affected_users'] = {user: count for user, count in user_rows}
        
        conn.close()
        return summary


class AlertManager:
    """
    Manager class to coordinate alert generation and handling.
    """
    
    def __init__(self):
        self.alert_system = AlertSystem()
        self.active_alerts = []
    
    def process_anomalies(self, anomalies):
        """
        Process a list of anomalies and generate appropriate alerts.
        
        Args:
            anomalies (list): List of anomaly dictionaries
        """
        for anomaly in anomalies:
            self.alert_system.trigger_alert(anomaly)
            self.active_alerts.append(anomaly)
    
    def get_active_alerts(self):
        """
        Get the list of active alerts.
        
        Returns:
            list: List of active alerts
        """
        return self.active_alerts
    
    def get_alert_statistics(self, days=7):
        """
        Get statistics about alerts over the specified period.
        
        Args:
            days (int): Number of days to analyze
        
        Returns:
            dict: Statistics about alerts
        """
        return self.alert_system.get_alert_summary(days)


# Example usage and testing
if __name__ == "__main__":
    from datetime import timedelta
    
    # Create sample anomalies for testing
    sample_anomalies = [
        {
            'timestamp': datetime.now() - timedelta(minutes=5),
            'username': 'alice',
            'ip_address': '192.168.1.100',
            'severity': 'high',
            'anomaly_type': 'unusual_time',
            'details': 'Login at 3 AM, unusual for this user'
        },
        {
            'timestamp': datetime.now() - timedelta(minutes=10),
            'username': 'bob',
            'ip_address': '203.0.113.10',
            'severity': 'medium',
            'anomaly_type': 'location_change',
            'details': 'Login from new IP address'
        },
        {
            'timestamp': datetime.now() - timedelta(minutes=15),
            'username': 'charlie',
            'ip_address': '10.0.0.5',
            'severity': 'low',
            'anomaly_type': 'high_frequency',
            'details': 'Higher than usual login frequency'
        }
    ]
    
    # Test the alert manager
    alert_manager = AlertManager()
    alert_manager.process_anomalies(sample_anomalies)
    
    print("Active alerts processed.")
    
    # Get alert statistics
    stats = alert_manager.get_alert_statistics(days=1)
    print(f"\nAlert statistics: {stats}")
    
    # Get recent alerts from DB
    recent_alerts = alert_manager.alert_system.get_recent_alerts(minutes=60)
    print(f"\nRecent alerts in DB: {len(recent_alerts)}")
    for alert in recent_alerts[:3]:  # Show first 3
        print(f"  - {alert}")