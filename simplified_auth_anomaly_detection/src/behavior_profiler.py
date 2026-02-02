import pandas as pd
import numpy as np
import pickle
from datetime import datetime, timedelta
from collections import defaultdict


class UserProfile:
    """
    Represents a user's behavioral profile
    """
    
    def __init__(self, username):
        self.username = username
        self.login_times = []  # List of hours when user typically logs in
        self.preferred_days = set()  # Set of days of week user typically logs in (0=Monday, 6=Sunday)
        self.common_locations = set()  # Set of IP addresses/user locations
        self.login_frequency_per_day = 0  # Average number of logins per day
        self.success_rate = 0.0  # Success rate of login attempts
        self.failed_attempts_recent = 0  # Count of recent failed attempts
        
    def update_profile(self, log_df):
        """
        Update the user profile based on new log data
        """
        user_logs = log_df[log_df['username'] == self.username]
        
        if len(user_logs) == 0:
            return
            
        # Update login times (hours)
        self.login_times = user_logs['timestamp'].dt.hour.tolist()
        
        # Update preferred days
        self.preferred_days = set(user_logs['timestamp'].dt.dayofweek.tolist())
        
        # Update common locations (IP addresses)
        self.common_locations = set(user_logs['ip_address'].tolist())
        
        # Calculate login frequency per day
        if len(user_logs) > 0:
            min_date = user_logs['timestamp'].min()
            max_date = user_logs['timestamp'].max()
            days_span = (max_date - min_date).days + 1  # +1 to include both start and end days
            self.login_frequency_per_day = len(user_logs) / days_span if days_span > 0 else len(user_logs)
            
        # Calculate success rate
        successful_logins = len(user_logs[user_logs['event_type'] == 'successful_login'])
        total_logins = len(user_logs)
        self.success_rate = successful_logins / total_logins if total_logins > 0 else 0.0
        
        # Count recent failed attempts (last 24 hours)
        recent_threshold = datetime.now() - timedelta(hours=24)
        recent_failed = user_logs[
            (user_logs['timestamp'] > recent_threshold) & 
            (user_logs['event_type'] == 'failed_login')
        ]
        self.failed_attempts_recent = len(recent_failed)
    
    def get_behavior_summary(self):
        """
        Get a summary of the user's behavior
        """
        return {
            'username': self.username,
            'login_times_avg': np.mean(self.login_times) if self.login_times else None,
            'preferred_days': list(self.preferred_days) if self.preferred_days else None,
            'common_locations': list(self.common_locations) if self.common_locations else None,
            'login_frequency_per_day': self.login_frequency_per_day,
            'success_rate': self.success_rate
        }
    
    def is_anomalous_login(self, timestamp, ip_address, event_type='successful_login'):
        """
        Check if a login is anomalous based on the user's profile
        Returns a tuple (is_anomalous, severity, reason)
        """
        hour = timestamp.hour
        day_of_week = timestamp.dayofweek
        
        # Check if login time is unusual
        if self.login_times:
            avg_login_hour = np.mean(self.login_times)
            time_diff = abs(hour - avg_login_hour)
            if time_diff > 4:  # More than 4 hours from average
                return True, 'medium', f'Login at hour {hour} differs from typical hour {avg_login_hour:.1f} by {time_diff} hours'
        
        # Check if day is unusual
        if self.preferred_days and day_of_week not in self.preferred_days:
            return True, 'medium', f'Login on day {day_of_week} ({["Mon","Tue","Wed","Thu","Fri","Sat","Sun"][day_of_week]}) is unusual for this user'
        
        # Check if location is unusual
        if self.common_locations and ip_address not in self.common_locations:
            return True, 'high', f'Login from unusual location/IP: {ip_address}'
        
        # Check for high recent failed attempts
        if self.failed_attempts_recent > 5:
            return True, 'high', f'High number of recent failed attempts ({self.failed_attempts_recent}) before this login'
        
        return False, 'normal', 'Login matches typical user behavior'


class BehaviorProfiler:
    """
    Manages user behavior profiles for anomaly detection
    """
    
    def __init__(self):
        self.profiles = {}  # Dictionary mapping username to UserProfile
    
    def create_profile_for_user(self, username, log_df):
        """
        Create or update a profile for a specific user
        """
        if username not in self.profiles:
            self.profiles[username] = UserProfile(username)
        
        self.profiles[username].update_profile(log_df)
    
    def create_profiles_from_logs(self, log_df):
        """
        Create behavior profiles for all users in the log data
        """
        unique_users = log_df['username'].unique()
        
        for user in unique_users:
            if pd.notna(user):  # Only create profiles for non-null usernames
                self.create_profile_for_user(user, log_df)
    
    def get_user_profile(self, username):
        """
        Get the profile for a specific user
        """
        return self.profiles.get(username, None)
    
    def get_all_profiles(self):
        """
        Get all user profiles
        """
        return self.profiles
    
    def is_anomalous_activity(self, username, timestamp, ip_address, event_type='successful_login'):
        """
        Check if an activity is anomalous for a specific user
        """
        profile = self.get_user_profile(username)
        if profile:
            return profile.is_anomalous_login(timestamp, ip_address, event_type)
        else:
            # If no profile exists, treat as potentially anomalous
            return True, 'medium', f'No profile found for user {username}'
    
    def save_profiles(self, filepath):
        """
        Save all profiles to a file
        """
        with open(filepath, 'wb') as f:
            pickle.dump(self.profiles, f)
    
    def load_profiles(self, filepath):
        """
        Load profiles from a file
        """
        with open(filepath, 'rb') as f:
            self.profiles = pickle.load(f)


# Example usage
if __name__ == "__main__":
    import pandas as pd
    from datetime import datetime
    
    # Create sample data
    sample_data = {
        'timestamp': [
            datetime(2023, 1, 15, 9, 30),
            datetime(2023, 1, 15, 10, 15),
            datetime(2023, 1, 16, 9, 45),
            datetime(2023, 1, 17, 9, 20),
        ],
        'username': ['alice', 'alice', 'alice', 'bob'],
        'ip_address': ['192.168.1.10', '192.168.1.10', '192.168.1.11', '10.0.0.5'],
        'event_type': ['successful_login', 'successful_login', 'successful_login', 'successful_login']
    }
    
    df = pd.DataFrame(sample_data)
    
    # Create profiler and build profiles
    profiler = BehaviorProfiler()
    profiler.create_profiles_from_logs(df)
    
    # Test anomaly detection
    is_anomalous, severity, reason = profiler.is_anomalous_activity(
        'alice', 
        datetime(2023, 1, 18, 22, 30),  # Late evening login
        '192.168.1.100'  # Different IP
    )
    
    print(f"Anomalous: {is_anomalous}, Severity: {severity}, Reason: {reason}")
    
    # Print user profile summary
    profile = profiler.get_user_profile('alice')
    if profile:
        print("Alice's profile:", profile.get_behavior_summary())