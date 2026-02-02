import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.cluster import DBSCAN
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings('ignore')


class StatisticalAnomalyDetector:
    """
    Statistical methods for anomaly detection in authentication logs.
    """
    
    def __init__(self):
        self.threshold_percentile = 95  # Threshold for statistical anomalies
        self.z_score_threshold = 3.0    # Z-score threshold for outliers
    
    def detect_by_frequency(self, log_df, window_hours=24, threshold_multiplier=3):
        """
        Detect anomalies based on login frequency compared to historical patterns.
        
        Args:
            log_df (pd.DataFrame): DataFrame containing authentication logs
            window_hours (int): Time window in hours to calculate frequency
            threshold_multiplier (float): Multiplier for determining anomaly threshold
        
        Returns:
            list: List of anomalous events
        """
        if 'timestamp' not in log_df.columns:
            raise ValueError("DataFrame must contain 'timestamp' column")
        
        anomalies = []
        
        # Group by user to analyze individual patterns
        for user in log_df['username'].unique():
            user_logs = log_df[log_df['username'] == user].copy()
            user_logs = user_logs.sort_values('timestamp')
            
            # Calculate rolling login frequency
            user_logs.loc[:, 'freq_window_start'] = user_logs['timestamp'] - timedelta(hours=window_hours)
            
            for idx, row in user_logs.iterrows():
                # Count logins in the past window_hours
                time_window = (row['timestamp'] - timedelta(hours=window_hours), row['timestamp'])
                past_logins = user_logs[
                    (user_logs['timestamp'] >= time_window[0]) & 
                    (user_logs['timestamp'] <= time_window[1])
                ]
                
                current_freq = len(past_logins)
                
                # Calculate historical average frequency for this user
                if len(user_logs) > 1:
                    historical_freqs = []
                    for i in range(len(user_logs)):
                        window_start = user_logs.iloc[i]['timestamp'] - timedelta(hours=window_hours)
                        window_end = user_logs.iloc[i]['timestamp']
                        
                        hist_window = user_logs[
                            (user_logs['timestamp'] >= window_start) & 
                            (user_logs['timestamp'] <= window_end)
                        ]
                        historical_freqs.append(len(hist_window))
                    
                    if historical_freqs:
                        avg_freq = np.mean(historical_freqs)
                        std_freq = np.std(historical_freqs)
                        
                        # Define threshold as mean + multiplier * std
                        threshold = avg_freq + threshold_multiplier * std_freq
                        
                        if current_freq > threshold:
                            anomalies.append({
                                'timestamp': row['timestamp'],
                                'username': row['username'],
                                'ip_address': row.get('ip_address', 'Unknown'),
                                'event_type': row.get('event_type', 'Unknown'),
                                'anomaly_type': 'high_frequency',
                                'severity': 'high' if current_freq > 2 * threshold else 'medium',
                                'details': f'Login frequency ({current_freq}) exceeds threshold ({threshold:.2f})'
                            })
        
        return anomalies
    
    def detect_by_time_patterns(self, log_df, time_threshold_hours=2):
        """
        Detect anomalies based on unusual login times compared to user's historical patterns.
        
        Args:
            log_df (pd.DataFrame): DataFrame containing authentication logs
            time_threshold_hours (float): Threshold in hours for unusual login times
        
        Returns:
            list: List of anomalous events
        """
        anomalies = []
        
        for user in log_df['username'].unique():
            user_logs = log_df[log_df['username'] == user].copy()
            
            if len(user_logs) == 0:
                continue
            
            # Calculate user's typical login hours
            typical_hours = user_logs['timestamp'].dt.hour.mode()
            if len(typical_hours) > 0:
                most_common_hour = typical_hours[0]
            else:
                continue  # Skip if no clear pattern
            
            # Find logins that are far from typical hours
            for _, row in user_logs.iterrows():
                current_hour = row['timestamp'].hour
                hour_diff = min(abs(current_hour - most_common_hour), 
                               24 - abs(current_hour - most_common_hour))  # Handle wraparound
                
                if hour_diff > time_threshold_hours:
                    anomalies.append({
                        'timestamp': row['timestamp'],
                        'username': row['username'],
                        'ip_address': row.get('ip_address', 'Unknown'),
                        'event_type': row.get('event_type', 'Unknown'),
                        'anomaly_type': 'unusual_time',
                        'severity': 'medium',
                        'details': f'Login at hour {current_hour} differs from typical hour {most_common_hour} by {hour_diff} hours'
                    })
        
        return anomalies
    
    def detect_by_location(self, log_df, distance_threshold_km=1000):
        """
        Detect anomalies based on unusual login locations.
        Note: This is a simplified version that assumes IP geolocation data is available.
        
        Args:
            log_df (pd.DataFrame): DataFrame containing authentication logs
            distance_threshold_km (float): Threshold distance for considering location unusual
        
        Returns:
            list: List of anomalous events
        """
        anomalies = []
        
        # For simplicity, we'll use IP address changes as proxy for location changes
        # In a real system, you'd use geolocation data
        for user in log_df['username'].unique():
            user_logs = log_df[log_df['username'] == user].copy()
            user_logs = user_logs.sort_values('timestamp')
            
            unique_ips = user_logs['ip_address'].unique()
            
            # If user is logging in from many different IPs in a short time, flag as anomaly
            for i in range(1, len(user_logs)):
                prev_row = user_logs.iloc[i-1]
                curr_row = user_logs.iloc[i]
                
                # Check if IP changed significantly
                if prev_row['ip_address'] != curr_row['ip_address']:
                    time_diff = curr_row['timestamp'] - prev_row['timestamp']
                    
                    # If IP changed and the time difference is small, could be suspicious
                    if time_diff < timedelta(hours=1):
                        anomalies.append({
                            'timestamp': curr_row['timestamp'],
                            'username': curr_row['username'],
                            'ip_address': curr_row['ip_address'],
                            'event_type': curr_row.get('event_type', 'Unknown'),
                            'anomaly_type': 'location_change',
                            'severity': 'medium',
                            'details': f'Rapid IP change from {prev_row["ip_address"]} to {curr_row["ip_address"]} in {time_diff}'
                        })
        
        return anomalies


class MachineLearningAnomalyDetector:
    """
    Machine learning-based anomaly detection for authentication logs.
    """
    
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = []
        self.model_trained = False
    
    def prepare_features(self, log_df):
        """
        Prepare features for ML-based anomaly detection.
        
        Args:
            log_df (pd.DataFrame): DataFrame containing authentication logs
        
        Returns:
            np.array: Feature matrix ready for ML model
        """
        features = pd.DataFrame()
        
        # Time-based features
        if 'timestamp' in log_df.columns:
            features['hour'] = log_df['timestamp'].dt.hour
            features['day_of_week'] = log_df['timestamp'].dt.dayofweek
            features['day_of_month'] = log_df['timestamp'].dt.day
            features['month'] = log_df['timestamp'].dt.month
        
        # User-based features
        if 'username' in log_df.columns:
            # Encode usernames numerically
            if not hasattr(self.label_encoder, 'classes_') or len(self.label_encoder.classes_) == 0:
                encoded_users = self.label_encoder.fit_transform(log_df['username'].astype(str))
            else:
                # Handle unseen labels by assigning them a default value
                unique_users = log_df['username'].astype(str)
                encoded_users = []
                for user in unique_users:
                    try:
                        encoded_val = self.label_encoder.transform([user])[0]
                    except ValueError:
                        # Assign a new value for unseen users
                        encoded_val = len(self.label_encoder.classes_)
                    encoded_users.append(encoded_val)
            features['username_encoded'] = encoded_users
        
        # IP-based features
        if 'ip_address' in log_df.columns:
            # For simplicity, we'll use a hash of the IP address
            features['ip_hash'] = log_df['ip_address'].apply(lambda x: hash(x) % 10000 if pd.notna(x) else -1)
        
        # Event type features
        if 'event_type' in log_df.columns:
            event_mapping = {'successful_login': 1, 'failed_login': 0, 'logout': 2, 'access': 3}
            features['event_type_encoded'] = log_df['event_type'].map(event_mapping).fillna(-1)
        
        # Interaction features
        if 'hour' in features.columns and 'username_encoded' in features.columns:
            features['hour_username_interaction'] = features['hour'] * features['username_encoded']
        
        # Fill NaN values with 0
        features = features.fillna(0)
        
        self.feature_columns = features.columns.tolist()
        return features.values
    
    def train_model(self, log_df):
        """
        Train the ML model on historical log data.
        
        Args:
            log_df (pd.DataFrame): DataFrame containing historical authentication logs
        """
        features = self.prepare_features(log_df)
        
        # Scale features
        scaled_features = self.scaler.fit_transform(features)
        
        # Train isolation forest
        self.isolation_forest.fit(scaled_features)
        self.model_trained = True
    
    def predict_anomalies(self, log_df):
        """
        Predict anomalies using the trained ML model.
        
        Args:
            log_df (pd.DataFrame): DataFrame containing authentication logs to analyze
        
        Returns:
            list: List of detected anomalies
        """
        if not self.model_trained:
            raise ValueError("Model must be trained before predicting anomalies")
        
        features = self.prepare_features(log_df)
        scaled_features = self.scaler.transform(features)
        
        # Get anomaly predictions (-1 for anomaly, 1 for normal)
        anomaly_predictions = self.isolation_forest.predict(scaled_features)
        anomaly_scores = self.isolation_forest.decision_function(scaled_features)
        
        anomalies = []
        for i, (pred, score) in enumerate(zip(anomaly_predictions, anomaly_scores)):
            if pred == -1:  # Anomaly detected
                row = log_df.iloc[i]
                severity = 'high' if score < -0.5 else 'medium'
                
                anomalies.append({
                    'timestamp': row.get('timestamp', 'Unknown'),
                    'username': row.get('username', 'Unknown'),
                    'ip_address': row.get('ip_address', 'Unknown'),
                    'event_type': row.get('event_type', 'Unknown'),
                    'anomaly_type': 'ml_detected',
                    'severity': severity,
                    'anomaly_score': score,
                    'details': f'ML model detected anomaly with score {score:.3f}'
                })
        
        return anomalies


class AnomalyDetector:
    """
    Main class that combines statistical and ML-based anomaly detection methods.
    """
    
    def __init__(self):
        self.stat_detector = StatisticalAnomalyDetector()
        self.ml_detector = MachineLearningAnomalyDetector()
        self.all_anomalies = []
    
    def detect_anomalies(self, log_df, use_statistical=True, use_ml=True):
        """
        Detect anomalies using both statistical and ML methods.
        
        Args:
            log_df (pd.DataFrame): DataFrame containing authentication logs
            use_statistical (bool): Whether to use statistical detection methods
            use_ml (bool): Whether to use ML-based detection methods
        
        Returns:
            list: Combined list of detected anomalies
        """
        all_anomalies = []
        
        if use_statistical:
            # Run statistical anomaly detection methods
            freq_anomalies = self.stat_detector.detect_by_frequency(log_df)
            time_anomalies = self.stat_detector.detect_by_time_patterns(log_df)
            location_anomalies = self.stat_detector.detect_by_location(log_df)
            
            all_anomalies.extend(freq_anomalies)
            all_anomalies.extend(time_anomalies)
            all_anomalies.extend(location_anomalies)
        
        if use_ml:
            # Train and run ML-based anomaly detection
            if len(log_df) > 10:  # Need sufficient data to train
                self.ml_detector.train_model(log_df)
                ml_anomalies = self.ml_detector.predict_anomalies(log_df)
                all_anomalies.extend(ml_anomalies)
        
        # Combine and deduplicate anomalies
        seen_events = set()
        unique_anomalies = []
        
        for anomaly in all_anomalies:
            event_key = (anomaly['timestamp'], anomaly['username'], anomaly['ip_address'])
            if event_key not in seen_events:
                seen_events.add(event_key)
                unique_anomalies.append(anomaly)
        
        self.all_anomalies = unique_anomalies
        return unique_anomalies
    
    def get_anomaly_report(self):
        """
        Generate a summary report of detected anomalies.
        
        Returns:
            dict: Summary report of anomalies
        """
        if not self.all_anomalies:
            return {'message': 'No anomalies detected'}
        
        report = {
            'total_anomalies': len(self.all_anomalies),
            'anomalies_by_severity': {},
            'anomalies_by_type': {},
            'top_users_affected': {},
            'timeline': {}
        }
        
        # Count by severity
        for anomaly in self.all_anomalies:
            severity = anomaly['severity']
            report['anomalies_by_severity'][severity] = report['anomalies_by_severity'].get(severity, 0) + 1
            
            anomaly_type = anomaly['anomaly_type']
            report['anomalies_by_type'][anomaly_type] = report['anomalies_by_type'].get(anomaly_type, 0) + 1
            
            username = anomaly['username']
            report['top_users_affected'][username] = report['top_users_affected'].get(username, 0) + 1
        
        # Sort top affected users
        report['top_users_affected'] = dict(
            sorted(report['top_users_affected'].items(), key=lambda x: x[1], reverse=True)[:10]
        )
        
        # Group by date for timeline
        for anomaly in self.all_anomalies:
            date = anomaly['timestamp'].date()
            report['timeline'][str(date)] = report['timeline'].get(str(date), 0) + 1
        
        return report


# Example usage and testing
if __name__ == "__main__":
    # Create sample log data for testing
    np.random.seed(42)
    dates = pd.date_range(start='2023-01-01', periods=500, freq='1H')
    
    # Create realistic log data
    sample_data = {
        'timestamp': [],
        'username': [],
        'ip_address': [],
        'event_type': []
    }
    
    usernames = ['alice', 'bob', 'charlie', 'diana'] * 125  # Repeat to get 500 entries
    ip_addresses = (
        ['192.168.1.10'] * 200 +  # Regular IPs
        ['192.168.1.11'] * 150 + 
        ['10.0.0.5'] * 100 + 
        ['203.0.113.10'] * 30 +  # Suspicious IP range
        ['198.51.100.5'] * 20      # Another suspicious IP
    )[:500]
    
    event_types = (
        ['successful_login'] * 350 +
        ['failed_login'] * 100 +
        ['logout'] * 50
    )[:500]
    
    # Shuffle the data to make it more realistic
    np.random.shuffle(usernames)
    np.random.shuffle(ip_addresses)
    np.random.shuffle(event_types)
    
    sample_data['timestamp'] = dates
    sample_data['username'] = usernames
    sample_data['ip_address'] = ip_addresses
    sample_data['event_type'] = event_types
    
    df = pd.DataFrame(sample_data)
    
    # Test the anomaly detector
    detector = AnomalyDetector()
    anomalies = detector.detect_anomalies(df, use_statistical=True, use_ml=True)
    
    print(f"Detected {len(anomalies)} anomalies:")
    for i, anomaly in enumerate(anomalies[:5]):  # Show first 5 anomalies
        print(f"{i+1}. {anomaly}")
    
    # Generate report
    report = detector.get_anomaly_report()
    print("\nAnomaly Report:")
    print(report)