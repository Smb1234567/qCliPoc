"""
Real-time Streaming Analytics Module
Processes authentication logs in real-time using stream processing techniques
"""
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import asyncio
import queue
import threading
from collections import deque, defaultdict
import time
import json
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

class SlidingWindowProcessor:
    """
    Processes data using sliding windows for real-time analytics
    """
    
    def __init__(self, window_size_minutes=5, slide_interval_minutes=1):
        self.window_size = timedelta(minutes=window_size_minutes)
        self.slide_interval = timedelta(minutes=slide_interval_minutes)
        self.windows = {}  # Store data for each window
        self.last_slide_time = datetime.min
        self.aggregated_metrics = defaultdict(deque)
        
    def add_event(self, event):
        """
        Add an event to the current window
        """
        current_time = event.get('timestamp', datetime.now())
        
        # Create a window key based on the current time window
        window_start = current_time - timedelta(seconds=current_time.second,
                                               microseconds=current_time.microsecond)
        # Round down to nearest interval
        interval_minutes = self.slide_interval.seconds // 60
        rounded_minute = (window_start.minute // interval_minutes) * interval_minutes
        window_start = window_start.replace(minute=rounded_minute, second=0, microsecond=0)
        
        if window_start not in self.windows:
            self.windows[window_start] = []
        
        self.windows[window_start].append(event)
        
        # Slide windows if necessary
        if current_time - self.last_slide_time >= self.slide_interval:
            self.slide_windows(current_time)
            self.last_slide_time = current_time
    
    def slide_windows(self, current_time):
        """
        Remove old windows that are outside the window size
        """
        cutoff_time = current_time - self.window_size
        windows_to_remove = []
        
        for window_start in self.windows:
            if window_start < cutoff_time:
                windows_to_remove.append(window_start)
        
        for window_start in windows_to_remove:
            del self.windows[window_start]
    
    def get_current_window_data(self):
        """
        Get all data in the current windows
        """
        all_data = []
        current_time = datetime.now()
        cutoff_time = current_time - self.window_size
        
        for window_start, events in self.windows.items():
            if window_start >= cutoff_time:
                all_data.extend(events)
        
        return all_data
    
    def calculate_window_metrics(self):
        """
        Calculate metrics for the current window
        """
        data = self.get_current_window_data()
        if not data:
            return {}
        
        df = pd.DataFrame(data)
        
        metrics = {
            'total_events': len(data),
            'unique_users': df['username'].nunique() if 'username' in df.columns else 0,
            'unique_ips': df['ip_address'].nunique() if 'ip_address' in df.columns else 0,
            'successful_logins': len(df[df['event_type'] == 'successful_login']) if 'event_type' in df.columns else 0,
            'failed_logins': len(df[df['event_type'] == 'failed_login']) if 'event_type' in df.columns else 0,
            'login_rate_per_minute': len(data) / (self.window_size.total_seconds() / 60) if self.window_size.total_seconds() > 0 else 0
        }
        
        # Calculate user-specific metrics
        if 'username' in df.columns:
            user_metrics = {}
            for user in df['username'].unique():
                user_data = df[df['username'] == user]
                user_metrics[user] = {
                    'login_count': len(user_data),
                    'success_rate': len(user_data[user_data['event_type'] == 'successful_login']) / len(user_data) if len(user_data) > 0 else 0,
                    'unique_ips': user_data['ip_address'].nunique() if 'ip_address' in user_data.columns else 0
                }
            metrics['user_metrics'] = user_metrics
        
        return metrics


class RealTimeAnomalyDetector:
    """
    Real-time anomaly detection using streaming data
    """
    
    def __init__(self, window_size_minutes=5):
        self.window_processor = SlidingWindowProcessor(window_size_minutes=window_size_minutes)
        self.anomaly_models = {}  # Models for different types of anomalies
        self.baseline_calculated = False
        self.baseline_data = []
        self.baseline_window_count = 0
        self.BASELINE_WINDOW_THRESHOLD = 10  # Number of windows to establish baseline
        
    def process_event(self, event):
        """
        Process a single incoming event
        """
        # Add event to window processor
        self.window_processor.add_event(event)
        
        # If we haven't established a baseline yet, collect data
        if not self.baseline_calculated and self.window_processor.last_slide_time != datetime.min:
            self.baseline_data.append(event)
            self.baseline_window_count += 1
            
            if self.baseline_window_count >= self.BASELINE_WINDOW_THRESHOLD:
                self.establish_baseline()
        
        # Detect anomalies if baseline is established
        if self.baseline_calculated:
            return self.detect_streaming_anomalies()
        else:
            return []
    
    def establish_baseline(self):
        """
        Establish baseline behavior from initial data
        """
        print("Establishing baseline behavior...")
        
        # Calculate baseline metrics
        df = pd.DataFrame(self.baseline_data)
        
        # Calculate user behavior baselines
        self.user_baselines = {}
        if 'username' in df.columns:
            for user in df['username'].unique():
                user_data = df[df['username'] == user]
                self.user_baselines[user] = {
                    'avg_login_frequency': len(user_data) / (self.BASELINE_WINDOW_THRESHOLD * 5),  # Per minute
                    'common_ips': user_data['ip_address'].value_counts().head(3).index.tolist() if 'ip_address' in user_data.columns else [],
                    'preferred_times': user_data['timestamp'].dt.hour.value_counts().head(3).index.tolist() if 'timestamp' in user_data.columns else []
                }
        
        # Train anomaly detection models
        self.train_models()
        
        self.baseline_calculated = True
        print("Baseline established successfully!")
    
    def train_models(self):
        """
        Train models for different types of anomalies
        """
        # For frequency-based anomalies, we'll use a simple statistical model
        # In practice, you might use more sophisticated approaches
        
        # Prepare features for ML model
        data = self.window_processor.get_current_window_data()
        if not data:
            return
        
        df = pd.DataFrame(data)
        
        # Create features for isolation forest
        feature_data = []
        for user in df['username'].unique():
            user_data = df[df['username'] == user]
            features = [
                len(user_data),  # Login count
                user_data['timestamp'].dt.hour.mean() if 'timestamp' in user_data.columns else 0,  # Avg hour
                user_data['ip_address'].nunique() if 'ip_address' in user_data.columns else 0  # Unique IPs
            ]
            feature_data.append(features)
        
        if feature_data:
            feature_array = np.array(feature_data)
            scaler = StandardScaler()
            scaled_features = scaler.fit_transform(feature_array)
            
            # Train isolation forest
            iso_forest = IsolationForest(contamination=0.1, random_state=42)
            iso_forest.fit(scaled_features)
            
            self.anomaly_models['isolation_forest'] = {
                'model': iso_forest,
                'scaler': scaler
            }
    
    def detect_streaming_anomalies(self):
        """
        Detect anomalies in the current streaming window
        """
        anomalies = []
        
        # Get current window metrics
        metrics = self.window_processor.calculate_window_metrics()
        
        # Check for volume anomalies
        if 'login_rate_per_minute' in metrics:
            # Compare to historical baseline
            historical_avg = getattr(self, 'historical_avg_rate', 1.0)  # Default to 1 per minute
            current_rate = metrics['login_rate_per_minute']
            
            if current_rate > historical_avg * 3:  # 3x higher than normal
                anomalies.append({
                    'timestamp': datetime.now(),
                    'anomaly_type': 'volume_spike',
                    'severity': 'high',
                    'metric_value': current_rate,
                    'baseline_value': historical_avg,
                    'details': f'Login rate spike: {current_rate:.2f} vs baseline {historical_avg:.2f} per minute'
                })
        
        # Check for ML-based anomalies
        if 'isolation_forest' in self.anomaly_models:
            data = self.window_processor.get_current_window_data()
            if data:
                df = pd.DataFrame(data)
                
                # Prepare features
                feature_data = []
                usernames = []
                for user in df['username'].unique():
                    user_data = df[df['username'] == user]
                    features = [
                        len(user_data),
                        user_data['timestamp'].dt.hour.mean() if 'timestamp' in user_data.columns else 0,
                        user_data['ip_address'].nunique() if 'ip_address' in user_data.columns else 0
                    ]
                    feature_data.append(features)
                    usernames.append(user)
                
                if feature_data:
                    feature_array = np.array(feature_data)
                    scaled_features = self.anomaly_models['isolation_forest']['scaler'].transform(feature_array)
                    predictions = self.anomaly_models['isolation_forest']['model'].predict(scaled_features)
                    
                    for i, pred in enumerate(predictions):
                        if pred == -1:  # Anomaly detected
                            anomalies.append({
                                'timestamp': datetime.now(),
                                'username': usernames[i],
                                'anomaly_type': 'behavioral_pattern',
                                'severity': 'medium',
                                'details': f'ML-detected anomaly for user {usernames[i]}'
                            })
        
        # Check for user-specific anomalies
        if hasattr(self, 'user_baselines') and 'user_metrics' in metrics:
            for username, user_metric in metrics['user_metrics'].items():
                if username in self.user_baselines:
                    baseline = self.user_baselines[username]
                    
                    # Check for unusual IP
                    if user_metric['unique_ips'] > len(baseline['common_ips']) * 2:
                        anomalies.append({
                            'timestamp': datetime.now(),
                            'username': username,
                            'anomaly_type': 'unusual_ip',
                            'severity': 'medium',
                            'details': f'User {username} logging in from {user_metric["unique_ips"]} IPs vs baseline of {len(baseline["common_ips"])}'
                        })
        
        return anomalies


class StreamProcessor:
    """
    Main class for handling real-time stream processing
    """
    
    def __init__(self, window_size_minutes=5):
        self.real_time_detector = RealTimeAnomalyDetector(window_size_minutes=window_size_minutes)
        self.event_queue = queue.Queue()
        self.is_running = False
        self.worker_thread = None
        
    def start_processing(self):
        """
        Start the stream processing in a separate thread
        """
        self.is_running = True
        self.worker_thread = threading.Thread(target=self._process_events)
        self.worker_thread.daemon = True
        self.worker_thread.start()
        print("Stream processing started...")
    
    def stop_processing(self):
        """
        Stop the stream processing
        """
        self.is_running = False
        if self.worker_thread:
            self.worker_thread.join()
        print("Stream processing stopped.")
    
    def _process_events(self):
        """
        Internal method to process events from the queue
        """
        while self.is_running:
            try:
                # Get event from queue with timeout
                event = self.event_queue.get(timeout=1)
                anomalies = self.real_time_detector.process_event(event)
                
                # Handle anomalies (in a real system, you'd send to alerting system)
                for anomaly in anomalies:
                    print(f"Real-time anomaly detected: {anomaly}")
                
                self.event_queue.task_done()
            except queue.Empty:
                continue  # No events to process, continue loop
    
    def add_event(self, event):
        """
        Add an event to the processing queue
        """
        self.event_queue.put(event)
    
    def get_current_metrics(self):
        """
        Get current streaming metrics
        """
        return self.real_time_detector.window_processor.calculate_window_metrics()


# Example usage
if __name__ == "__main__":
    import random
    
    # Create stream processor
    processor = StreamProcessor(window_size_minutes=2)
    processor.start_processing()
    
    # Simulate incoming events
    base_time = datetime.now()
    usernames = ['alice', 'bob', 'charlie', 'diana']
    ip_addresses = ['192.168.1.10', '192.168.1.11', '10.0.0.5', '203.0.113.10']
    event_types = ['successful_login', 'failed_login', 'logout']
    
    print("Simulating real-time events...")
    
    try:
        for i in range(50):
            event_time = base_time + timedelta(seconds=i*2)  # 2 seconds apart
            event = {
                'timestamp': event_time,
                'username': random.choice(usernames),
                'ip_address': random.choice(ip_addresses),
                'event_type': random.choice(event_types)
            }
            
            processor.add_event(event)
            time.sleep(0.1)  # Small delay to simulate real-time processing
        
        # Let it run a bit more to see anomalies
        time.sleep(5)
        
    except KeyboardInterrupt:
        print("\nStopping stream processing...")
    finally:
        processor.stop_processing()
    
    # Get final metrics
    metrics = processor.get_current_metrics()
    print(f"\nCurrent metrics: {metrics}")