import sys
import os
import argparse
from datetime import datetime

# Add the src directory to the path so we can import our modules
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from log_ingestor import LogIngestor
from behavior_profiler import BehaviorProfiler
from anomaly_detector import AnomalyDetector

# Import our new innovative modules
from advanced_anomaly_detector import AdvancedAnomalyDetector
from biometric_analyzer import BehavioralBiometricAnalyzer
from streaming_analytics import StreamProcessor
from xai_module import XAIAnomalyReporter
from federated_learning import FederatedLearningCoordinator

from alert_system import AlertManager


def main():
    parser = argparse.ArgumentParser(description='AI-Based Anomaly Detection System for Authentication Logs')
    parser.add_argument('--log-file', type=str, help='Path to the authentication log file')
    parser.add_argument('--log-dir', type=str, help='Directory containing authentication log files')
    parser.add_argument('--format', type=str, default='auto',
                       choices=['auto', 'syslog', 'json', 'csv', 'apache_common', 'apache_combined'],
                       help='Format of the authentication logs')
    parser.add_argument('--dashboard', action='store_true',
                       help='Start the dashboard interface')
    parser.add_argument('--demo', action='store_true',
                       help='Run a demonstration of the system')
    parser.add_argument('--innovative', action='store_true',
                       help='Run with innovative features enabled')

    args = parser.parse_args()

    if args.dashboard:
        # Import and run the dashboard
        from dashboard.app import run_dashboard
        run_dashboard()
        return

    if args.demo:
        run_demo()
        return

    if not args.log_file and not args.log_dir:
        print("Error: Either --log-file or --log-dir must be specified")
        parser.print_help()
        return

    # Initialize system components
    print("Initializing AI Anomaly Detection System...")
    ingestor = LogIngestor()
    profiler = BehaviorProfiler()
    detector = AnomalyDetector()
    alert_manager = AlertManager()

    # Initialize innovative components
    if args.innovative:
        print("Initializing innovative features...")
        advanced_detector = AdvancedAnomalyDetector()
        biometric_analyzer = BehavioralBiometricAnalyzer()
        stream_processor = StreamProcessor(window_size_minutes=2)
        xai_reporter = XAIAnomalyReporter()
        fed_coordinator = FederatedLearningCoordinator()

        # Set up a simulated federation with multiple clients
        client_configs = {
            'client_1': {
                'model_type': 'isolation_forest',
                'local_data': None  # Will be set later with actual data
            },
            'client_2': {
                'model_type': 'isolation_forest',
                'local_data': None
            },
            'client_3': {
                'model_type': 'isolation_forest',
                'local_data': None
            }
        }
        fed_coordinator.setup_federation(client_configs)

    # Process logs
    print("Processing authentication logs...")
    if args.log_file:
        df = ingestor.read_log_file(args.log_file, log_format=args.format)
    else:
        # Get all log files from directory
        import glob
        log_files = glob.glob(os.path.join(args.log_dir, "*.log")) + \
                   glob.glob(os.path.join(args.log_dir, "*.txt"))
        df = ingestor.read_multiple_log_files(log_files, log_format=args.format)

    print(f"Loaded {len(df)} log entries")

    if len(df) == 0:
        print("No log entries found. Exiting.")
        return

    # Create user behavior profiles
    print("Creating user behavior profiles...")
    profiler.create_profiles_from_logs(df)
    print(f"Created profiles for {len(profiler.get_all_profiles())} users")

    # Detect anomalies
    print("Detecting anomalies...")
    anomalies = detector.detect_anomalies(df, use_statistical=True, use_ml=True)
    print(f"Detected {len(anomalies)} anomalies")

    # Apply innovative features if enabled
    if args.innovative:
        print("Applying advanced anomaly detection...")
        advanced_anomalies = advanced_detector.detect_advanced_anomalies(df)
        print(f"Detected {len(advanced_anomalies)} advanced anomalies")

        # Combine anomalies
        all_anomalies = anomalies + advanced_anomalies

        print("Performing explainable AI analysis...")
        xai_report = xai_reporter.generate_explained_report(df, all_anomalies, profiler.get_all_profiles())

        print("Running federated learning simulation...")
        # Update client data with current dataset
        for client_id in fed_coordinator.federated_detector.clients:
            fed_coordinator.federated_detector.clients[client_id]['model'].local_data = df
        fed_coordinator.run_federated_training(rounds=2, clients_per_round=3)

        print("Processing through real-time streaming analytics...")
        stream_processor.start_processing()

        # Simulate streaming some events
        for _, row in df.head(20).iterrows():  # Process first 20 events
            event = row.to_dict()
            stream_processor.add_event(event)

        # Get final metrics
        stream_metrics = stream_processor.get_current_metrics()
        print(f"Streaming metrics: {stream_metrics}")
        stream_processor.stop_processing()

        # Update anomalies with federated results
        fed_anomalies = fed_coordinator.federated_detector.detect_anomalies_federated(df)
        print(f"Detected {len(fed_anomalies)} anomalies with federated model")

        # Combine all anomalies
        all_anomalies = anomalies + advanced_anomalies + fed_anomalies

    else:
        all_anomalies = anomalies

    # Generate alerts
    print("Generating alerts...")
    alert_manager.process_anomalies(all_anomalies)

    # Print summary
    print("\n--- Detection Summary ---")
    print(f"Total log entries processed: {len(df)}")
    print(f"Unique users: {df['username'].nunique() if 'username' in df.columns else 0}")
    print(f"Anomalies detected: {len(all_anomalies)}")

    if all_anomalies:
        severity_counts = {}
        for anomaly in all_anomalies:
            sev = anomaly['severity']
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        print("Anomalies by severity:")
        for severity, count in severity_counts.items():
            print(f"  {severity.capitalize()}: {count}")

    print(f"\nAlerts generated: {len(alert_manager.get_active_alerts())}")

    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    df.to_csv(f"processed_logs_{timestamp}.csv", index=False)
    profiler.save_profiles(f"profiles_{timestamp}.pkl")

    print(f"\nResults saved to processed_logs_{timestamp}.csv and profiles_{timestamp}.pkl")

    # Print innovative features summary if enabled
    if args.innovative:
        print("\n--- Innovative Features Summary ---")
        print(f"Advanced anomalies detected: {len(advanced_anomalies)}")
        print(f"Federated anomalies detected: {len(fed_anomalies)}")
        print(f"XAI report generated with {xai_report['summary']['total_explained']} explained anomalies")
        print(f"Federated learning completed {fed_coordinator.federated_detector.round_number} rounds")
        print(f"Streaming analytics processed events with metrics: {stream_metrics}")


def run_demo():
    """
    Run a demonstration of the system with sample data.
    """
    print("Running AI Anomaly Detection System Demo...")
    
    # Import required modules
    import pandas as pd
    import numpy as np
    from datetime import datetime, timedelta
    
    # Create sample log data
    print("Creating sample authentication logs...")
    np.random.seed(42)
    
    # Generate realistic sample data
    base_time = datetime.now() - timedelta(days=7)
    timestamps = [base_time + timedelta(hours=x) for x in range(0, 168, 2)]  # Every 2 hours for a week
    
    sample_data = {
        'timestamp': [],
        'username': [],
        'ip_address': [],
        'event_type': []
    }
    
    usernames = ['alice', 'bob', 'charlie', 'diana', 'eve']
    ip_addresses = ['192.168.1.10', '192.168.1.11', '10.0.0.5', '10.0.0.6', '203.0.113.10', '198.51.100.5']
    event_types = ['successful_login', 'failed_login', 'logout']
    
    for ts in timestamps:
        # Simulate normal behavior for most entries
        if np.random.random() > 0.1:  # 90% normal
            sample_data['timestamp'].append(ts)
            sample_data['username'].append(np.random.choice(usernames[:4]))  # Exclude eve for normal
            sample_data['ip_address'].append(np.random.choice(ip_addresses[:4]))
            sample_data['event_type'].append(np.random.choice(['successful_login', 'logout'], p=[0.8, 0.2]))
        else:  # 10% anomalous
            sample_data['timestamp'].append(ts)
            sample_data['username'].append(np.random.choice(usernames))  # Include all users
            sample_data['ip_address'].append(np.random.choice(ip_addresses))  # Include suspicious IPs
            sample_data['event_type'].append(np.random.choice(['successful_login', 'failed_login'], p=[0.7, 0.3]))
    
    df = pd.DataFrame(sample_data)
    print(f"Generated {len(df)} sample log entries")
    
    # Initialize system components
    print("\nInitializing system components...")
    profiler = BehaviorProfiler()
    detector = AnomalyDetector()
    alert_manager = AlertManager()
    
    # Create user behavior profiles
    print("Creating user behavior profiles...")
    profiler.create_profiles_from_logs(df)
    print(f"Created profiles for {len(profiler.get_all_profiles())} users")
    
    # Detect anomalies
    print("Detecting anomalies...")
    anomalies = detector.detect_anomalies(df, use_statistical=True, use_ml=True)
    print(f"Detected {len(anomalies)} anomalies")
    
    # Generate alerts
    print("Generating alerts...")
    alert_manager.process_anomalies(anomalies)
    
    # Print demo results
    print("\n--- Demo Results ---")
    print(f"Total log entries processed: {len(df)}")
    print(f"Unique users: {df['username'].nunique()}")
    print(f"Anomalies detected: {len(anomalies)}")
    
    if anomalies:
        print("\nSample anomalies detected:")
        for i, anomaly in enumerate(anomalies[:5]):  # Show first 5 anomalies
            print(f"  {i+1}. {anomaly['severity'].upper()} - {anomaly.get('details', 'N/A')}")
    
    print(f"\nAlerts generated: {len(alert_manager.get_active_alerts())}")
    
    # Show user behavior summary for one user
    sample_user = 'alice'
    user_profile = profiler.get_user_profile(sample_user)
    if user_profile:
        print(f"\nBehavior summary for {sample_user}:")
        summary = user_profile.get_behavior_summary()
        for key, value in summary.items():
            if value is not None:
                print(f"  {key}: {value}")
    
    print("\nDemo completed successfully!")
    print("\nTo run the dashboard and visualize results, execute: python app.py --dashboard")


if __name__ == "__main__":
    main()