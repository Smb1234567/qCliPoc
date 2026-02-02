import logging
from datetime import datetime
import sqlite3
import os


class AlertManager:
    """
    Manages the generation and storage of alerts based on detected anomalies
    """
    
    def __init__(self, db_path="alert_history.db", log_path="alerts.log"):
        self.active_alerts = []
        self.db_path = db_path
        self.log_path = log_path
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_path),
                logging.StreamHandler()  # Also print to console
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize database
        self.init_db()
    
    def init_db(self):
        """
        Initialize the SQLite database for storing alert history
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                username TEXT,
                ip_address TEXT,
                severity TEXT,
                anomaly_type TEXT,
                details TEXT,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def process_anomalies(self, anomalies):
        """
        Process a list of detected anomalies and generate alerts
        """
        for anomaly in anomalies:
            self.generate_alert(
                username=anomaly.get('username', 'Unknown'),
                ip_address=anomaly.get('ip_address', 'Unknown'),
                severity=anomaly.get('severity', 'medium'),
                anomaly_type=anomaly.get('anomaly_type', 'unknown'),
                details=anomaly.get('details', 'No details provided'),
                timestamp=anomaly.get('timestamp', datetime.now())
            )
    
    def generate_alert(self, username, ip_address, severity, anomaly_type, details, timestamp=None):
        """
        Generate an alert for an anomalous event
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        alert = {
            'timestamp': timestamp,
            'username': username,
            'ip_address': ip_address,
            'severity': severity,
            'anomaly_type': anomaly_type,
            'details': details,
            'status': 'active'
        }
        
        # Add to active alerts
        self.active_alerts.append(alert)
        
        # Log the alert
        self.logger.info(f"Alert triggered: {severity.upper()} SEVERITY: {details}")
        
        # Store in database
        self.store_alert_in_db(alert)
        
        return alert
    
    def store_alert_in_db(self, alert):
        """
        Store an alert in the SQLite database
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (timestamp, username, ip_address, severity, anomaly_type, details, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert['timestamp'].isoformat() if hasattr(alert['timestamp'], 'isoformat') else str(alert['timestamp']),
            alert['username'],
            alert['ip_address'],
            alert['severity'],
            alert['anomaly_type'],
            alert['details'],
            alert['status']
        ))
        
        conn.commit()
        conn.close()
    
    def get_active_alerts(self):
        """
        Get all active alerts
        """
        return [alert for alert in self.active_alerts if alert['status'] == 'active']
    
    def get_alerts_by_severity(self, severity):
        """
        Get alerts filtered by severity level
        """
        return [alert for alert in self.active_alerts 
                if alert['severity'] == severity and alert['status'] == 'active']
    
    def get_alerts_by_username(self, username):
        """
        Get alerts for a specific user
        """
        return [alert for alert in self.active_alerts 
                if alert['username'] == username and alert['status'] == 'active']
    
    def get_alert_history(self, limit=100):
        """
        Get alert history from the database
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM alerts 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        columns = ['id', 'timestamp', 'username', 'ip_address', 'severity', 'anomaly_type', 'details', 'status']
        
        alerts = []
        for row in rows:
            alert = dict(zip(columns, row))
            alerts.append(alert)
        
        conn.close()
        return alerts
    
    def acknowledge_alert(self, alert_id):
        """
        Acknowledge an alert (change its status)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('UPDATE alerts SET status = "acknowledged" WHERE id = ?', (alert_id,))
        conn.commit()
        conn.close()
        
        # Update in-memory alerts
        for alert in self.active_alerts:
            if alert.get('id') == alert_id:
                alert['status'] = 'acknowledged'
                break
    
    def clear_alert(self, alert_id):
        """
        Clear an alert (remove from active alerts)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('UPDATE alerts SET status = "cleared" WHERE id = ?', (alert_id,))
        conn.commit()
        conn.close()


# Example usage
if __name__ == "__main__":
    # Create alert manager
    alert_manager = AlertManager()
    
    # Generate some sample alerts
    alert_manager.generate_alert(
        username="alice",
        ip_address="192.168.1.100",
        severity="high",
        anomaly_type="unusual_location",
        details="Login from unusual IP for user alice"
    )
    
    alert_manager.generate_alert(
        username="bob",
        ip_address="10.0.0.50",
        severity="medium",
        anomaly_type="unusual_time",
        details="Login at unusual time for user bob"
    )
    
    print(f"Active alerts: {len(alert_manager.get_active_alerts())}")
    
    # Show alert history
    history = alert_manager.get_alert_history(limit=10)
    print(f"Recent alert history: {len(history)} records")