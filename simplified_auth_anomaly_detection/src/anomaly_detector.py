import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings('ignore')


class AnomalyDetector:
    """
    Anomaly detection using statistical and ML methods
    """
    
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = []
        
    def prepare_features(self, log_df):
        """
        Prepare features for ML-based anomaly detection
        """
        features = pd.DataFrame()
        
        # Time-based features
        features['hour'] = log_df['timestamp'].dt.hour
        features['day_of_week'] = log_df['timestamp'].dt.dayofweek
        features['minute'] = log_df['timestamp'].dt.minute
        
        # Encode categorical variables
        if 'username' in log_df.columns:
            # Handle NaN values in username column
            username_col = log_df['username'].fillna('unknown')
            features['username_encoded'] = self.label_encoder.fit_transform(username_col.astype(str))
        
        if 'ip_address' in log_df.columns:
            # Handle NaN values in ip_address column
            ip_col = log_df['ip_address'].fillna('0.0.0.0')
            features['ip_encoded'] = self.label_encoder.fit_transform(ip_col.astype(str))
        
        if 'event_type' in log_df.columns:
            event_col = log_df['event_type'].fillna('unknown')
            features['event_encoded'] = self.label_encoder.fit_transform(event_col.astype(str))
        
        # Normalize features
        features_scaled = self.scaler.fit_transform(features)
        
        return features_scaled, features.columns.tolist()
    
    def detect_statistical_anomalies(self, log_df):
        """
        Detect anomalies using statistical methods
        """
        anomalies = []
        
        # Check for unusual login times
        for user in log_df['username'].unique():
            if pd.isna(user):
                continue
                
            user_logs = log_df[log_df['username'] == user]
            
            if len(user_logs) == 0:
                continue
                
            # Calculate average login hour for the user
            avg_hour = user_logs['timestamp'].dt.hour.mean()
            
            for idx, row in user_logs.iterrows():
                hour = row['timestamp'].hour
                
                # Flag if login time is significantly different from user's average
                if abs(hour - avg_hour) > 6:  # More than 6 hours difference
                    anomalies.append({
                        'timestamp': row['timestamp'],
                        'username': row['username'],
                        'ip_address': row.get('ip_address', 'Unknown'),
                        'event_type': row.get('event_type', 'Unknown'),
                        'anomaly_type': 'unusual_time',
                        'severity': 'medium',
                        'details': f'Login at hour {hour} differs from typical hour {avg_hour:.1f} by {abs(hour - avg_hour)} hours'
                    })
        
        # Check for unusual IP addresses
        for user in log_df['username'].unique():
            if pd.isna(user):
                continue
                
            user_logs = log_df[log_df['username'] == user]
            common_ips = user_logs['ip_address'].value_counts()
            common_ips_set = set(common_ips.head(3).index)  # Top 3 common IPs
            
            for idx, row in user_logs.iterrows():
                if row['ip_address'] not in common_ips_set:
                    # Only flag if user has had multiple logins from common IPs before
                    if len(common_ips) > 0:
                        anomalies.append({
                            'timestamp': row['timestamp'],
                            'username': row['username'],
                            'ip_address': row['ip_address'],
                            'event_type': row.get('event_type', 'Unknown'),
                            'anomaly_type': 'unusual_location',
                            'severity': 'high',
                            'details': f'Login from unusual IP {row["ip_address"]} for user {row["username"]}'
                        })
        
        # Check for rapid successive failed attempts
        failed_attempts = log_df[log_df['event_type'] == 'failed_login']
        for user in failed_attempts['username'].unique():
            if pd.isna(user):
                continue
                
            user_failed = failed_attempts[failed_attempts['username'] == user].sort_values('timestamp')
            
            # Look for bursts of failed attempts
            for i in range(len(user_failed) - 4):  # At least 5 failed attempts
                window_start = user_failed.iloc[i]['timestamp']
                window_end = user_failed.iloc[i + 4]['timestamp']
                
                # If 5 or more failed attempts happen within 10 minutes
                if (window_end - window_start).total_seconds() < 600:  # 10 minutes
                    anomalies.append({
                        'timestamp': window_end,
                        'username': user,
                        'ip_address': user_failed.iloc[i]['ip_address'],
                        'event_type': 'failed_login',
                        'anomaly_type': 'brute_force',
                        'severity': 'high',
                        'details': f'Rapid succession of {len(user_failed)} failed login attempts for user {user}'
                    })
                    break  # Only report once per burst
        
        return anomalies
    
    def detect_ml_anomalies(self, log_df):
        """
        Detect anomalies using machine learning (Isolation Forest)
        """
        if len(log_df) < 10:  # Need sufficient data for ML
            return []
        
        try:
            # Prepare features for ML model
            features, feature_names = self.prepare_features(log_df)
            
            # Fit the isolation forest model
            predictions = self.isolation_forest.fit_predict(features)
            
            # Get anomaly scores (lower scores indicate anomalies)
            anomaly_scores = self.isolation_forest.decision_function(features)
            
            anomalies = []
            for i, (idx, row) in enumerate(log_df.iterrows()):
                if predictions[i] == -1:  # Anomaly detected by isolation forest
                    # Determine severity based on anomaly score
                    score = anomaly_scores[i]
                    if score < -0.5:
                        severity = 'high'
                    elif score < -0.2:
                        severity = 'medium'
                    else:
                        severity = 'low'
                    
                    anomalies.append({
                        'timestamp': row['timestamp'],
                        'username': row['username'],
                        'ip_address': row.get('ip_address', 'Unknown'),
                        'event_type': row.get('event_type', 'Unknown'),
                        'anomaly_type': 'ml_detected',
                        'severity': severity,
                        'details': f'ML model detected anomaly with score {score:.3f}'
                    })
            
            return anomalies
        except Exception as e:
            print(f"ML anomaly detection failed: {e}")
            return []
    
    def detect_anomalies(self, log_df, use_statistical=True, use_ml=True):
        """
        Detect anomalies using both statistical and ML methods
        """
        all_anomalies = []
        
        if use_statistical:
            statistical_anomalies = self.detect_statistical_anomalies(log_df)
            all_anomalies.extend(statistical_anomalies)
        
        if use_ml:
            ml_anomalies = self.detect_ml_anomalies(log_df)
            all_anomalies.extend(ml_anomalies)
        
        # Remove duplicates based on timestamp and username
        seen = set()
        unique_anomalies = []
        for anomaly in all_anomalies:
            key = (anomaly['timestamp'], anomaly['username'])
            if key not in seen:
                seen.add(key)
                unique_anomalies.append(anomaly)
        
        return unique_anomalies


# Example usage
if __name__ == "__main__":
    import pandas as pd
    import numpy as np
    
    # Create sample data
    np.random.seed(42)
    dates = pd.date_range(start='2023-01-01', periods=100, freq='1H')
    
    sample_data = {
        'timestamp': [],
        'username': [],
        'ip_address': [],
        'event_type': []
    }
    
    usernames = ['alice', 'bob', 'charlie'] * 34  # 102, trim to 100
    ip_addresses = (
        ['192.168.1.10'] * 60 +
        ['192.168.1.11'] * 30 +
        ['10.0.0.5'] * 10
    )[:100]
    
    event_types = (
        ['successful_login'] * 70 +
        ['failed_login'] * 20 +
        ['logout'] * 10
    )[:100]
    
    np.random.shuffle(usernames)
    np.random.shuffle(ip_addresses)
    np.random.shuffle(event_types)
    
    sample_data['timestamp'] = dates
    sample_data['username'] = usernames
    sample_data['ip_address'] = ip_addresses
    sample_data['event_type'] = event_types
    
    df = pd.DataFrame({k: v[:100] for k, v in sample_data.items()})
    
    # Test anomaly detection
    detector = AnomalyDetector()
    anomalies = detector.detect_anomalies(df, use_statistical=True, use_ml=True)
    
    print(f"Detected {len(anomalies)} anomalies:")
    for i, anomaly in enumerate(anomalies[:5]):
        print(f"{i+1}. {anomaly['severity'].upper()} - {anomaly['details']}")