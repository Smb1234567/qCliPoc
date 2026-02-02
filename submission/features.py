from src.behavior_profiler import BehaviorProfiler
from src.anomaly_detector import MachineLearningAnomalyDetector
import pandas as pd
import os

def main():
    print("--- Feature Engineering PoC ---")
    
    # Load parsed logs
    if not os.path.exists('parsed_logs.csv'):
        print("Error: parsed_logs.csv not found. Run parser.py first.")
        return

    df = pd.read_csv('parsed_logs.csv')
    
    # Convert timestamp back to datetime
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])

    print(f"Loaded {len(df)} log entries.")

    # 1. Behavior Profiling Features
    print("\nExtracting User Behavior Profiles...")
    profiler = BehaviorProfiler()
    profiler.create_profiles_from_logs(df)
    
    sample_user = df['username'].iloc[0] if not df.empty else 'admin'
    profile = profiler.get_user_profile(sample_user)
    
    if profile:
        print(f"\nProfile Summary for '{sample_user}':")
        summary = profile.get_behavior_summary()
        for k, v in summary.items():
            print(f"  {k}: {v}")

    # 2. ML Feature Extraction
    print("\nGenerating ML Feature Matrix...")
    detector = MachineLearningAnomalyDetector()
    features = detector.prepare_features(df)
    
    print(f"Feature Matrix Shape: {features.shape}")
    print("Feature Columns:", detector.feature_columns)
    
    # Show a sample feature vector
    print("\nSample Feature Vector (First row):")
    print(features[0])

if __name__ == "__main__":
    main()
