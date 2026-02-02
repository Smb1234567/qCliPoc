from src.anomaly_detector import AnomalyDetector
import pandas as pd
import os

def main():
    print("--- ML Model PoC ---")
    
    # Load parsed logs
    if not os.path.exists('parsed_logs.csv'):
        print("Error: parsed_logs.csv not found. Run parser.py first.")
        return

    df = pd.read_csv('parsed_logs.csv')
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])

    print(f"Training model on {len(df)} records...")
    
    # Initialize and run detector (Statistical + ML)
    detector = AnomalyDetector()
    
    # This trains the Isolation Forest and detects anomalies
    anomalies = detector.detect_anomalies(df)
    
    print(f"\nDetected {len(anomalies)} anomalies.")
    
    if anomalies:
        print("\nTop 3 Anomalies:")
        for i, anomaly in enumerate(anomalies[:3]):
            print(f"[{i+1}] User: {anomaly['username']}, Severity: {anomaly['severity']}")
            print(f"    Type: {anomaly['anomaly_type']}")
            print(f"    Details: {anomaly['details']}")
            if 'anomaly_score' in anomaly:
                print(f"    ML Score: {anomaly['anomaly_score']:.4f}")
    
    # Generate report
    report = detector.get_anomaly_report()
    print("\nAnomaly Report Summary:")
    print(f"Total: {report.get('total_anomalies')}")
    print(f"By Severity: {report.get('anomalies_by_severity')}")

if __name__ == "__main__":
    main()
