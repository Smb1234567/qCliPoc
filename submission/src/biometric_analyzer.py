"""
Biometric Behavioral Analysis Module
Analyzes keystroke dynamics, mouse movements, and other behavioral biometrics
"""
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import statistics
from scipy import stats
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

class KeystrokeDynamicsAnalyzer:
    """
    Analyzes keystroke timing patterns for user authentication verification
    """
    
    def __init__(self):
        self.user_keystroke_profiles = {}
        self.global_keystroke_stats = {}
        
    def extract_keystroke_features(self, session_data):
        """
        Extract keystroke timing features from session data
        Expected format: [{'timestamp': datetime, 'keystroke_type': 'down/up', 'key': 'a', 'session_id': '123'}, ...]
        """
        features = {
            'hold_times': [],  # Time between key down and key up
            'flight_times': [],  # Time between key up and next key down
            'latency_times': [],  # Time between key down events
            'typing_speed': []  # Characters per minute
        }
        
        # Group by session
        sessions = {}
        for event in session_data:
            sid = event['session_id']
            if sid not in sessions:
                sessions[sid] = []
            sessions[sid].append(event)
        
        for session_id, events in sessions.items():
            # Sort events by timestamp
            events.sort(key=lambda x: x['timestamp'])
            
            # Calculate keystroke features
            for i in range(len(events)-1):
                current = events[i]
                next_event = events[i+1]
                
                # Hold time: time between key down and key up for same key
                if current['keystroke_type'] == 'down':
                    # Look for corresponding key up
                    for j in range(i+1, len(events)):
                        if (events[j]['key'] == current['key'] and 
                            events[j]['keystroke_type'] == 'up' and
                            events[j]['timestamp'] > current['timestamp']):
                            hold_time = (events[j]['timestamp'] - current['timestamp']).total_seconds()
                            features['hold_times'].append(hold_time)
                            break
                
                # Flight time: time between key up and next key down
                if current['keystroke_type'] == 'up' and next_event['keystroke_type'] == 'down':
                    flight_time = (next_event['timestamp'] - current['timestamp']).total_seconds()
                    features['flight_times'].append(flight_time)
                
                # Latency time: time between key down events
                if current['keystroke_type'] == 'down' and next_event['keystroke_type'] == 'down':
                    latency_time = (next_event['timestamp'] - current['timestamp']).total_seconds()
                    features['latency_times'].append(latency_time)
        
        # Calculate typing speed (characters per minute)
        if len(events) > 0:
            start_time = min([e['timestamp'] for e in events])
            end_time = max([e['timestamp'] for e in events])
            duration_minutes = (end_time - start_time).total_seconds() / 60
            if duration_minutes > 0:
                features['typing_speed'].append(len(events) / duration_minutes)
        
        return features
    
    def create_keystroke_profile(self, username, keystroke_features):
        """
        Create a behavioral profile for a user based on keystroke dynamics
        """
        profile = {
            'hold_time_mean': statistics.mean(keystroke_features['hold_times']) if keystroke_features['hold_times'] else 0,
            'hold_time_std': statistics.stdev(keystroke_features['hold_times']) if len(keystroke_features['hold_times']) > 1 else 0,
            'flight_time_mean': statistics.mean(keystroke_features['flight_times']) if keystroke_features['flight_times'] else 0,
            'flight_time_std': statistics.stdev(keystroke_features['flight_times']) if len(keystroke_features['flight_times']) > 1 else 0,
            'latency_time_mean': statistics.mean(keystroke_features['latency_times']) if keystroke_features['latency_times'] else 0,
            'latency_time_std': statistics.stdev(keystroke_features['latency_times']) if len(keystroke_features['latency_times']) > 1 else 0,
            'typing_speed_mean': statistics.mean(keystroke_features['typing_speed']) if keystroke_features['typing_speed'] else 0,
            'typing_speed_std': statistics.stdev(keystroke_features['typing_speed']) if len(keystroke_features['typing_speed']) > 1 else 0,
            'created_at': datetime.now(),
            'samples_count': len(keystroke_features['hold_times']) + len(keystroke_features['flight_times']) + len(keystroke_features['latency_times'])
        }
        
        self.user_keystroke_profiles[username] = profile
        return profile
    
    def assess_keystroke_anomaly(self, username, current_features):
        """
        Assess how anomalous current keystroke patterns are compared to user profile
        """
        if username not in self.user_keystroke_profiles:
            return {'is_anomaly': True, 'confidence': 0.9, 'details': 'No keystroke profile for user'}
        
        profile = self.user_keystroke_profiles[username]
        anomaly_score = 0
        details = []
        
        # Check hold times
        if current_features['hold_times']:
            current_hold_mean = statistics.mean(current_features['hold_times'])
            if profile['hold_time_std'] > 0:
                z_score = abs(current_hold_mean - profile['hold_time_mean']) / profile['hold_time_std']
                if z_score > 2:
                    anomaly_score += z_score * 0.3
                    details.append(f"Hold time deviation: z-score {z_score:.2f}")
        
        # Check flight times
        if current_features['flight_times']:
            current_flight_mean = statistics.mean(current_features['flight_times'])
            if profile['flight_time_std'] > 0:
                z_score = abs(current_flight_mean - profile['flight_time_mean']) / profile['flight_time_std']
                if z_score > 2:
                    anomaly_score += z_score * 0.3
                    details.append(f"Flight time deviation: z-score {z_score:.2f}")
        
        # Check typing speed
        if current_features['typing_speed']:
            current_speed_mean = statistics.mean(current_features['typing_speed'])
            if profile['typing_speed_std'] > 0:
                z_score = abs(current_speed_mean - profile['typing_speed_mean']) / profile['typing_speed_std']
                if z_score > 2:
                    anomaly_score += z_score * 0.4
                    details.append(f"Typing speed deviation: z-score {z_score:.2f}")
        
        is_anomaly = anomaly_score > 1.0
        confidence = min(anomaly_score, 1.0)
        
        return {
            'is_anomaly': is_anomaly,
            'confidence': confidence,
            'anomaly_score': anomaly_score,
            'details': '; '.join(details) if details else 'Normal keystroke pattern'
        }


class MouseMovementAnalyzer:
    """
    Analyzes mouse movement patterns for behavioral biometrics
    """
    
    def __init__(self):
        self.user_mouse_profiles = {}
        
    def extract_mouse_features(self, mouse_data):
        """
        Extract mouse movement features from mouse tracking data
        Expected format: [{'timestamp': datetime, 'x': int, 'y': int, 'event_type': 'move/click', 'session_id': '123'}, ...]
        """
        features = {
            'movement_speeds': [],
            'accelerations': [],
            'direction_changes': [],
            'click_intervals': [],
            'path_efficiency': []  # Straight-line distance vs actual path
        }
        
        # Group by session
        sessions = {}
        for event in mouse_data:
            sid = event['session_id']
            if sid not in sessions:
                sessions[sid] = []
            sessions[sid].append(event)
        
        for session_id, events in sessions.items():
            # Sort by timestamp
            events.sort(key=lambda x: x['timestamp'])
            
            # Calculate mouse features
            positions = [(e['x'], e['y']) for e in events if e['event_type'] == 'move']
            timestamps = [e['timestamp'] for e in events if e['event_type'] == 'move']
            clicks = [e for e in events if e['event_type'] == 'click']
            
            # Movement speeds and accelerations
            for i in range(1, len(positions)):
                dx = positions[i][0] - positions[i-1][0]
                dy = positions[i][1] - positions[i-1][1]
                dist = (dx**2 + dy**2)**0.5
                dt = (timestamps[i] - timestamps[i-1]).total_seconds()
                
                if dt > 0:
                    speed = dist / dt
                    features['movement_speeds'].append(speed)
                    
                    if i > 1:
                        prev_dt = (timestamps[i-1] - timestamps[i-2]).total_seconds()
                        if prev_dt > 0:
                            prev_speed = ((positions[i-1][0] - positions[i-2][0])**2 + 
                                         (positions[i-1][1] - positions[i-2][1])**2)**0.5 / prev_dt
                            acceleration = (speed - prev_speed) / dt
                            features['accelerations'].append(acceleration)
            
            # Direction changes (changes in movement direction)
            for i in range(1, len(positions)-1):
                v1 = (positions[i][0] - positions[i-1][0], positions[i][1] - positions[i-1][1])
                v2 = (positions[i+1][0] - positions[i][0], positions[i+1][1] - positions[i][1])
                
                # Calculate angle between vectors
                dot_product = v1[0]*v2[0] + v1[1]*v2[1]
                norms = (v1[0]**2 + v1[1]**2)**0.5 * (v2[0]**2 + v2[1]**2)**0.5
                
                if norms > 0:
                    cos_angle = dot_product / norms
                    angle = np.arccos(max(-1, min(1, cos_angle)))  # Clamp to [-1, 1] to avoid numerical errors
                    if angle > np.pi / 4:  # More than 45 degrees change
                        features['direction_changes'].append(angle)
            
            # Click intervals
            click_timestamps = [c['timestamp'] for c in clicks]
            for i in range(1, len(click_timestamps)):
                interval = (click_timestamps[i] - click_timestamps[i-1]).total_seconds()
                features['click_intervals'].append(interval)
            
            # Path efficiency (straight line vs actual path)
            if len(positions) > 1:
                start_pos = positions[0]
                end_pos = positions[-1]
                straight_dist = ((end_pos[0] - start_pos[0])**2 + (end_pos[1] - start_pos[1])**2)**0.5
                
                actual_path = 0
                for i in range(1, len(positions)):
                    dx = positions[i][0] - positions[i-1][0]
                    dy = positions[i][1] - positions[i-1][1]
                    actual_path += (dx**2 + dy**2)**0.5
                
                if actual_path > 0:
                    efficiency = straight_dist / actual_path
                    features['path_efficiency'].append(efficiency)
        
        return features
    
    def create_mouse_profile(self, username, mouse_features):
        """
        Create a behavioral profile for a user based on mouse movements
        """
        profile = {
            'speed_mean': statistics.mean(mouse_features['movement_speeds']) if mouse_features['movement_speeds'] else 0,
            'speed_std': statistics.stdev(mouse_features['movement_speeds']) if len(mouse_features['movement_speeds']) > 1 else 0,
            'acceleration_mean': statistics.mean(mouse_features['accelerations']) if mouse_features['accelerations'] else 0,
            'acceleration_std': statistics.stdev(mouse_features['accelerations']) if len(mouse_features['accelerations']) > 1 else 0,
            'direction_changes_mean': statistics.mean(mouse_features['direction_changes']) if mouse_features['direction_changes'] else 0,
            'click_interval_mean': statistics.mean(mouse_features['click_intervals']) if mouse_features['click_intervals'] else 0,
            'click_interval_std': statistics.stdev(mouse_features['click_intervals']) if len(mouse_features['click_intervals']) > 1 else 0,
            'path_efficiency_mean': statistics.mean(mouse_features['path_efficiency']) if mouse_features['path_efficiency'] else 0,
            'created_at': datetime.now(),
            'samples_count': len(mouse_features['movement_speeds']) + len(mouse_features['click_intervals'])
        }
        
        self.user_mouse_profiles[username] = profile
        return profile
    
    def assess_mouse_anomaly(self, username, current_features):
        """
        Assess how anomalous current mouse patterns are compared to user profile
        """
        if username not in self.user_mouse_profiles:
            return {'is_anomaly': True, 'confidence': 0.8, 'details': 'No mouse profile for user'}
        
        profile = self.user_mouse_profiles[username]
        anomaly_score = 0
        details = []
        
        # Check movement speeds
        if current_features['movement_speeds']:
            current_speed_mean = statistics.mean(current_features['movement_speeds'])
            if profile['speed_std'] > 0:
                z_score = abs(current_speed_mean - profile['speed_mean']) / profile['speed_std']
                if z_score > 2:
                    anomaly_score += z_score * 0.4
                    details.append(f"Mouse speed deviation: z-score {z_score:.2f}")
        
        # Check click intervals
        if current_features['click_intervals']:
            current_click_mean = statistics.mean(current_features['click_intervals'])
            if profile['click_interval_std'] > 0:
                z_score = abs(current_click_mean - profile['click_interval_mean']) / profile['click_interval_std']
                if z_score > 2:
                    anomaly_score += z_score * 0.3
                    details.append(f"Click interval deviation: z-score {z_score:.2f}")
        
        # Check path efficiency
        if current_features['path_efficiency']:
            current_efficiency_mean = statistics.mean(current_features['path_efficiency'])
            target_efficiency = profile['path_efficiency_mean']
            if target_efficiency > 0:
                efficiency_ratio = abs(current_efficiency_mean - target_efficiency) / target_efficiency
                if efficiency_ratio > 0.5:  # 50% deviation
                    anomaly_score += efficiency_ratio * 0.3
                    details.append(f"Path efficiency deviation: ratio {efficiency_ratio:.2f}")
        
        is_anomaly = anomaly_score > 1.0
        confidence = min(anomaly_score, 1.0)
        
        return {
            'is_anomaly': is_anomaly,
            'confidence': confidence,
            'anomaly_score': anomaly_score,
            'details': '; '.join(details) if details else 'Normal mouse pattern'
        }


class BehavioralBiometricAnalyzer:
    """
    Main class combining all biometric behavioral analysis
    """
    
    def __init__(self):
        self.keystroke_analyzer = KeystrokeDynamicsAnalyzer()
        self.mouse_analyzer = MouseMovementAnalyzer()
        self.biometric_threshold = 0.7  # Threshold for considering behavior anomalous
        
    def process_biometric_session(self, username, keystroke_data=None, mouse_data=None):
        """
        Process a session with biometric data and assess anomaly
        """
        results = {
            'username': username,
            'timestamp': datetime.now(),
            'keystroke_analysis': None,
            'mouse_analysis': None,
            'overall_anomaly': False,
            'confidence': 0.0,
            'details': []
        }
        
        # Process keystroke data if available
        if keystroke_data:
            features = self.keystroke_analyzer.extract_keystroke_features(keystroke_data)
            analysis = self.keystroke_analyzer.assess_keystroke_anomaly(username, features)
            results['keystroke_analysis'] = analysis
            results['details'].append(f"Keystroke: {analysis['details']}")
            
            if analysis['is_anomaly']:
                results['overall_anomaly'] = True
                results['confidence'] = max(results['confidence'], analysis['confidence'])
        
        # Process mouse data if available
        if mouse_data:
            features = self.mouse_analyzer.extract_mouse_features(mouse_data)
            analysis = self.mouse_analyzer.assess_mouse_anomaly(username, features)
            results['mouse_analysis'] = analysis
            results['details'].append(f"Mouse: {analysis['details']}")
            
            if analysis['is_anomaly']:
                results['overall_anomaly'] = True
                results['confidence'] = max(results['confidence'], analysis['confidence'])
        
        return results
    
    def update_user_profile(self, username, keystroke_data=None, mouse_data=None):
        """
        Update user's biometric profile with new data
        """
        if keystroke_data:
            features = self.keystroke_analyzer.extract_keystroke_features(keystroke_data)
            self.keystroke_analyzer.create_keystroke_profile(username, features)
        
        if mouse_data:
            features = self.mouse_analyzer.extract_mouse_features(mouse_data)
            self.mouse_analyzer.create_mouse_profile(username, features)


# Example usage
if __name__ == "__main__":
    # Create sample biometric data for testing
    import random
    
    # Sample keystroke data
    base_time = datetime.now()
    keystroke_sample = []
    for i in range(50):
        event_time = base_time + timedelta(milliseconds=random.randint(0, 10000))
        keystroke_sample.append({
            'timestamp': event_time,
            'keystroke_type': random.choice(['down', 'up']),
            'key': random.choice(['a', 's', 'd', 'f', 'j', 'k', 'l']),
            'session_id': 'session_1'
        })
    
    # Sample mouse data
    mouse_sample = []
    x, y = 100, 100
    for i in range(100):
        event_time = base_time + timedelta(milliseconds=random.randint(0, 15000))
        x += random.randint(-10, 10)
        y += random.randint(-10, 10)
        mouse_sample.append({
            'timestamp': event_time,
            'x': x,
            'y': y,
            'event_type': random.choice(['move', 'click']),
            'session_id': 'session_1'
        })
    
    # Test the biometric analyzer
    analyzer = BehavioralBiometricAnalyzer()
    
    # Create initial profile
    analyzer.update_user_profile('test_user', keystroke_sample, mouse_sample)
    
    # Assess a new session
    result = analyzer.process_biometric_session('test_user', keystroke_sample, mouse_sample)
    
    print("Biometric Analysis Result:")
    print(f"Overall Anomaly: {result['overall_anomaly']}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Details: {result['details']}")