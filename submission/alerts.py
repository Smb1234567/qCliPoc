from src.alert_system import AlertManager
from src.anomaly_detector import AnomalyDetector
import pandas as pd
import os

def main():
    print("--- Alert System PoC ---")
    
    # Load parsed logs
    if not os.path.exists('parsed_logs.csv'):
        print("Error: parsed_logs.csv not found. Run parser.py first.")
        return

    df = pd.read_csv('parsed_logs.csv')
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Detect anomalies first
    print("Detecting anomalies...")
    detector = AnomalyDetector()
    anomalies = detector.detect_anomalies(df)
    
    # Initialize Alert Manager
    manager = AlertManager()
    
    print(f"\nProcessing {len(anomalies)} anomalies for alerts...")
    manager.process_anomalies(anomalies)
    
    # Display Active Alerts (Simulation of alerting)
    print("\nGenerated Alerts:")
    active_alerts = manager.get_active_alerts()
    
    for alert in active_alerts:
        print(f"ALERT: User {alert.get('username')} login from {alert.get('ip_address')} at {alert.get('timestamp')} — Risk: {alert.get('severity').upper()}")
        print(f"       Reason: {alert.get('details')}")
        print("-" * 50)
        
    print(f"\nCheck 'alerts.log' and 'alert_history.db' for persistent records.")

if __name__ == "__main__":
    main()

