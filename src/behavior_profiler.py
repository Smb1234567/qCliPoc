import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
import pickle
import os


class UserProfile:
    """
    Represents a user's behavioral profile based on authentication logs.
    """
    
    def __init__(self, username):
        self.username = username
        self.login_patterns = {
            'times_of_day': [],  # Hour of day when user typically logs in
            'days_of_week': [],  # Day of week when user typically logs in
            'locations': [],     # IP addresses or geographic locations
            'devices': [],       # User agents or device types
            'session_duration': []  # Average session length
        }
        self.activity_patterns = {
            'frequency': 0,      # Login frequency per time period
            'success_rate': 0.0, # Success rate of login attempts
            'failed_attempts': [] # Times of failed attempts
        }
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
    
    def update_profile(self, log_data):
        """
        Update the user profile with new log data.
        
        Args:
            log_data (pd.DataFrame): DataFrame containing log entries for this user
        """
        self.updated_at = datetime.now()
        
        # Update login patterns
        if 'timestamp' in log_data.columns:
            times_of_day = log_data['timestamp'].dt.hour.tolist()
            days_of_week = log_data['timestamp'].dt.dayofweek.tolist()
            self.login_patterns['times_of_day'].extend(times_of_day)
            self.login_patterns['days_of_week'].extend(days_of_week)
        
        if 'ip_address' in log_data.columns:
            locations = log_data['ip_address'].dropna().tolist()
            self.login_patterns['locations'].extend(locations)
        
        if 'message' in log_data.columns:
            # Calculate session duration if logout info is available
            logins = log_data[log_data['event_type'] == 'successful_login']
            logouts = log_data[log_data['event_type'] == 'logout']
            
            # Simple heuristic: find next logout after each login
            for _, login in logins.iterrows():
                login_time = login['timestamp']
                user_logout = logouts[
                    (logouts['timestamp'] > login_time) & 
                    (logouts.get('username') == self.username if 'username' in logouts.columns else True)
                ].nsmallest(1, 'timestamp')
                
                if not user_logout.empty:
                    duration = (user_logout.iloc[0]['timestamp'] - login_time).total_seconds() / 3600  # hours
                    self.login_patterns['session_duration'].append(duration)
        
        # Update activity patterns
        total_attempts = len(log_data)
        successful_attempts = len(log_data[log_data['event_type'] == 'successful_login'])
        
        if total_attempts > 0:
            self.activity_patterns['success_rate'] = successful_attempts / total_attempts
        
        # Calculate login frequency (per day)
        if 'timestamp' in log_data.columns and len(log_data) > 0:
            time_range = log_data['timestamp'].max() - log_data['timestamp'].min()
            if time_range.days > 0:
                self.activity_patterns['frequency'] = len(log_data) / time_range.days
            else:
                self.activity_patterns['frequency'] = len(log_data)  # If all logs are from same day
        
        # Store failed attempts
        failed_logs = log_data[log_data['event_type'] == 'failed_login']
        if 'timestamp' in failed_logs.columns:
            self.activity_patterns['failed_attempts'].extend(failed_logs['timestamp'].tolist())
    
    def get_behavior_summary(self):
        """
        Get a summary of the user's behavior patterns.
        
        Returns:
            dict: Summary of behavior patterns
        """
        summary = {
            'username': self.username,
            'login_times_avg': np.mean(self.login_patterns['times_of_day']) if self.login_patterns['times_of_day'] else None,
            'preferred_days': list(set(self.login_patterns['days_of_week'])) if self.login_patterns['days_of_week'] else [],
            'common_locations': list(set(self.login_patterns['locations'])) if self.login_patterns['locations'] else [],
            'avg_session_duration': np.mean(self.login_patterns['session_duration']) if self.login_patterns['session_duration'] else None,
            'login_frequency_per_day': self.activity_patterns['frequency'],
            'success_rate': self.activity_patterns['success_rate']
        }
        return summary


class BehaviorProfiler:
    """
    Manages user profiles and creates behavioral baselines from authentication logs.
    """
    
    def __init__(self, profile_dir='profiles'):
        """
        Initialize the behavior profiler.
        
        Args:
            profile_dir (str): Directory to store user profiles
        """
        self.profiles = {}  # Dictionary mapping usernames to UserProfile objects
        self.profile_dir = profile_dir
        
        # Create profile directory if it doesn't exist
        os.makedirs(profile_dir, exist_ok=True)
    
    def create_profiles_from_logs(self, log_df):
        """
        Create or update user profiles from authentication logs.
        
        Args:
            log_df (pd.DataFrame): DataFrame containing authentication logs
        """
        if 'username' not in log_df.columns:
            raise ValueError("Log data must contain 'username' column")
        
        # Group logs by username
        grouped_logs = log_df.groupby('username')
        
        for username, user_logs in grouped_logs:
            if username not in self.profiles:
                self.profiles[username] = UserProfile(username)
            
            # Update the profile with user's log data
            self.profiles[username].update_profile(user_logs)
    
    def get_user_profile(self, username):
        """
        Get the profile for a specific user.
        
        Args:
            username (str): Username to retrieve profile for
        
        Returns:
            UserProfile: User's profile or None if not found
        """
        return self.profiles.get(username)
    
    def get_all_profiles(self):
        """
        Get all user profiles.
        
        Returns:
            dict: Dictionary of all user profiles
        """
        return self.profiles
    
    def save_profiles(self, filename=None):
        """
        Save all profiles to disk.
        
        Args:
            filename (str): Name of file to save profiles to. If None, uses default naming.
        """
        if filename is None:
            filename = os.path.join(self.profile_dir, f"profiles_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pkl")
        
        with open(filename, 'wb') as f:
            pickle.dump(self.profiles, f)
    
    def load_profiles(self, filename):
        """
        Load profiles from disk.
        
        Args:
            filename (str): Name of file to load profiles from
        """
        with open(filename, 'rb') as f:
            self.profiles = pickle.load(f)
    
    def calculate_similarity_score(self, username, current_activity):
        """
        Calculate how similar current activity is to user's baseline behavior.
        
        Args:
            username (str): Username to check
            current_activity (dict): Current activity to compare against baseline
        
        Returns:
            float: Similarity score between 0 and 1 (higher is more similar)
        """
        profile = self.get_user_profile(username)
        if not profile:
            return 0.0  # No profile exists, so very dissimilar
        
        scores = []
        
        # Check time of day similarity
        if 'timestamp' in current_activity and profile.login_patterns['times_of_day']:
            current_hour = current_activity['timestamp'].hour
            avg_login_hour = np.mean(profile.login_patterns['times_of_day'])
            hour_diff = abs(current_hour - avg_login_hour)
            # Normalize to 0-1 scale (0 difference = 1.0, max difference = 0.0)
            time_score = max(0, 1 - hour_diff/12)  # Max 12-hour difference
            scores.append(time_score)
        
        # Check location similarity
        if 'ip_address' in current_activity and profile.login_patterns['locations']:
            current_location = current_activity['ip_address']
            common_locations = set(profile.login_patterns['locations'])
            location_score = 1.0 if current_location in common_locations else 0.3  # Lower score for new location
            scores.append(location_score)
        
        # Check day of week similarity
        if 'timestamp' in current_activity and profile.login_patterns['days_of_week']:
            current_dow = current_activity['timestamp'].dayofweek
            preferred_days = set(profile.login_patterns['days_of_week'])
            dow_score = 1.0 if current_dow in preferred_days else 0.5  # Medium penalty for unusual day
            scores.append(dow_score)
        
        # Calculate average similarity score
        if scores:
            return sum(scores) / len(scores)
        else:
            return 0.5  # Default medium similarity if no comparison possible
    
    def detect_behavior_changes(self, username, threshold=0.3):
        """
        Detect significant changes in user behavior compared to historical patterns.
        
        Args:
            username (str): Username to analyze
            threshold (float): Threshold for detecting significant changes (0-1)
        
        Returns:
            dict: Analysis of behavior changes
        """
        profile = self.get_user_profile(username)
        if not profile:
            return {'error': 'Profile not found'}
        
        analysis = {
            'username': username,
            'profile_age_days': (datetime.now() - profile.created_at).days,
            'last_updated': profile.updated_at,
            'behavior_changed': False,
            'change_details': []
        }
        
        # Compare current patterns to historical averages
        if profile.login_patterns['times_of_day']:
            current_avg = np.mean(profile.login_patterns['times_of_day'])
            historical_std = np.std(profile.login_patterns['times_of_day'])
            
            if historical_std > 0:  # Avoid division by zero
                z_score = abs(current_avg - np.mean(profile.login_patterns['times_of_day'])) / historical_std
                if z_score > 2:  # Significant deviation
                    analysis['behavior_changed'] = True
                    analysis['change_details'].append({
                        'aspect': 'login_times',
                        'z_score': z_score,
                        'description': f'Login time patterns have significantly changed (z-score: {z_score:.2f})'
                    })
        
        # Add more change detection logic here as needed
        
        return analysis


# Example usage and testing
if __name__ == "__main__":
    # Create sample log data for testing
    sample_data = {
        'timestamp': pd.date_range(start='2023-01-01', periods=100, freq='1H'),
        'username': ['alice'] * 60 + ['bob'] * 40,
        'ip_address': ['192.168.1.10'] * 30 + ['192.168.1.11'] * 30 + ['10.0.0.5'] * 20 + ['10.0.0.6'] * 20,
        'event_type': ['successful_login'] * 50 + ['failed_login'] * 10 + ['successful_login'] * 30 + ['logout'] * 10
    }
    df = pd.DataFrame(sample_data)
    
    # Test the behavior profiler
    profiler = BehaviorProfiler()
    profiler.create_profiles_from_logs(df)
    
    # Print profile summary for alice
    alice_profile = profiler.get_user_profile('alice')
    if alice_profile:
        print("Alice's Profile Summary:")
        print(alice_profile.get_behavior_summary())
        
        # Test similarity scoring
        current_activity = {
            'timestamp': datetime(2023, 1, 2, 9, 0),  # 9 AM
            'ip_address': '192.168.1.10'
        }
        similarity = profiler.calculate_similarity_score('alice', current_activity)
        print(f"\nSimilarity score for Alice's current activity: {similarity:.2f}")
    
    # Test behavior change detection
    change_analysis = profiler.detect_behavior_changes('alice')
    print(f"\nBehavior change analysis for Alice: {change_analysis}")