"""
Explainable AI Module for Anomaly Detection
Provides interpretable explanations for why anomalies were detected
"""
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

class ExplanationGenerator:
    """
    Generates explanations for detected anomalies using rule-based approaches
    """

    def __init__(self):
        self.models = {}
        self.feature_names = []
        self.scalers = {}
        self.label_encoders = {}

    def prepare_features_for_explanation(self, log_df):
        """
        Prepare features that can be used for model training and explanation
        """
        features = pd.DataFrame()

        # Time-based features
        if 'timestamp' in log_df.columns:
            features['hour'] = log_df['timestamp'].dt.hour
            features['day_of_week'] = log_df['timestamp'].dt.dayofweek
            features['day_of_month'] = log_df['timestamp'].dt.day
            features['month'] = log_df['timestamp'].dt.month
            features['minute'] = log_df['timestamp'].dt.minute

            # Time since last login for each user
            features['time_since_last_login'] = 0.0
            for user in log_df['username'].unique():
                user_mask = log_df['username'] == user
                user_times = log_df[user_mask]['timestamp'].sort_values()
                time_diffs = [0] + [(user_times.iloc[i] - user_times.iloc[i-1]).total_seconds()/3600
                                   for i in range(1, len(user_times))]
                features.loc[user_mask, 'time_since_last_login'] = time_diffs[:sum(user_mask)]

        # User-based features
        if 'username' in log_df.columns:
            if 'username' not in self.label_encoders:
                self.label_encoders['username'] = LabelEncoder()
                encoded_users = self.label_encoders['username'].fit_transform(log_df['username'].astype(str))
            else:
                # Handle unseen users
                unique_users = log_df['username'].astype(str)
                encoded_users = []
                for user in unique_users:
                    try:
                        encoded_val = self.label_encoders['username'].transform([user])[0]
                    except ValueError:
                        # Assign a new value for unseen users
                        encoded_val = len(self.label_encoders['username'].classes_)
                    encoded_users.append(encoded_val)
            features['username_encoded'] = encoded_users

        # IP-based features
        if 'ip_address' in log_df.columns:
            if 'ip_address' not in self.label_encoders:
                self.label_encoders['ip_address'] = LabelEncoder()
                encoded_ips = self.label_encoders['ip_address'].fit_transform(log_df['ip_address'].astype(str))
            else:
                # Handle unseen IPs
                unique_ips = log_df['ip_address'].astype(str)
                encoded_ips = []
                for ip in unique_ips:
                    try:
                        encoded_val = self.label_encoders['ip_address'].transform([ip])[0]
                    except ValueError:
                        # Assign a new value for unseen IPs
                        encoded_val = len(self.label_encoders['ip_address'].classes_)
                    encoded_ips.append(encoded_val)
            features['ip_encoded'] = encoded_ips

            # Geographic features (simplified)
            features['is_private_ip'] = log_df['ip_address'].apply(
                lambda x: x.startswith(('10.', '172.', '192.168.')) if pd.notna(x) else False
            )

        # Event type features
        if 'event_type' in log_df.columns:
            event_mapping = {'successful_login': 1, 'failed_login': 0, 'logout': 2, 'access': 3}
            features['event_type_encoded'] = log_df['event_type'].map(event_mapping).fillna(-1)

        # Interaction features
        if 'hour' in features.columns and 'username_encoded' in features.columns:
            features['hour_username_interaction'] = features['hour'] * features['username_encoded']

        # Aggregated features per user
        if 'username_encoded' in features.columns:
            user_agg = log_df.groupby('username').agg({
                'timestamp': ['count', lambda x: x.max() - x.min()]
            }).round(2)
            user_agg.columns = ['login_count', 'active_period']
            user_agg = user_agg.reset_index()

            # Merge with features
            features = features.merge(user_agg, left_on='username_encoded',
                                     right_on=self.label_encoders['username'].transform(user_agg['username']),
                                     how='left')
            features['active_period'] = features['active_period'].dt.total_seconds() / (24*3600)  # Convert to days
            features['active_period'] = features['active_period'].fillna(0)

        # Fill NaN values with 0
        features = features.fillna(0)

        self.feature_names = features.columns.tolist()
        return features.values, features

    def generate_rule_based_explanation(self, log_record, user_profile=None):
        """
        Generate a rule-based explanation for why this record might be anomalous
        """
        explanations = []

        # Time-based rules
        if 'timestamp' in log_record:
            hour = log_record['timestamp'].hour
            if hour < 6 or hour > 22:  # Before 6 AM or after 10 PM
                explanations.append(f"Login at unusual time ({hour}:00)")

            dow = log_record['timestamp'].dayofweek
            if dow in [5, 6]:  # Weekend
                explanations.append("Login on weekend")

        # Location-based rules
        if 'ip_address' in log_record and user_profile:
            ip = log_record['ip_address']
            if 'common_locations' in user_profile and ip not in user_profile.get('common_locations', []):
                explanations.append(f"Login from new IP address: {ip}")

        # Frequency-based rules
        if 'username' in log_record and user_profile:
            if 'login_frequency_per_day' in user_profile:
                # This would require comparing to recent activity
                explanations.append("Activity pattern differs from baseline")

        return {
            'method': 'Rule-based',
            'explanations': explanations
        }

    def generate_feature_importance_explanation(self, log_record, log_df, anomalies):
        """
        Generate explanations based on feature importance relative to anomalies
        """
        # Calculate how this record differs from the norm
        explanations = []

        if 'timestamp' in log_record:
            # Check if this is an unusual time
            all_hours = log_df['timestamp'].dt.hour
            record_hour = log_record['timestamp'].hour
            hour_freq = (all_hours == record_hour).sum() / len(all_hours)

            # If this hour is rare (< 5% of all logins)
            if hour_freq < 0.05:
                explanations.append(f"Login at rare hour ({record_hour}:00, only {hour_freq:.1%} of logins occur at this time)")

        if 'ip_address' in log_record:
            # Check if this IP is rare
            all_ips = log_df['ip_address']
            record_ip = log_record['ip_address']
            ip_freq = (all_ips == record_ip).sum() / len(all_ips)

            if ip_freq < 0.05:
                explanations.append(f"Login from rare IP ({record_ip}, only {ip_freq:.1%} of logins from this IP)")

        # Check if this user has unusual activity compared to others
        if 'username' in log_record:
            user_logins = len(log_df[log_df['username'] == log_record['username']])
            total_logins = len(log_df)
            user_freq = user_logins / total_logins

            # If this user has very few logins (less than 1% of total)
            if user_freq < 0.01:
                explanations.append(f"Rare user account (only {user_freq:.1%} of all logins)")

        return {
            'method': 'Feature Importance',
            'explanations': explanations
        }

    def generate_comprehensive_explanation(self, log_record, log_df, anomalies, user_profile=None):
        """
        Generate a comprehensive explanation combining multiple methods
        """
        explanation = {
            'record': log_record,
            'rule_based': self.generate_rule_based_explanation(log_record, user_profile),
            'feature_importance': self.generate_feature_importance_explanation(log_record, log_df, anomalies)
        }

        return explanation


class XAIAnomalyReporter:
    """
    Generates comprehensive reports with explanations for detected anomalies
    """

    def __init__(self):
        self.explanation_generator = ExplanationGenerator()
        self.reports = []

    def generate_explained_report(self, log_df, anomalies, user_profiles=None):
        """
        Generate a report with explanations for all anomalies
        """
        print("Generating explained anomaly report...")

        explained_anomalies = []

        for anomaly in anomalies:
            # Find the corresponding log record
            mask = (
                (log_df['timestamp'] == anomaly['timestamp']) &
                (log_df['username'] == anomaly['username']) &
                (log_df['ip_address'] == anomaly['ip_address'])
            )

            if mask.any():
                log_record = log_df[mask].iloc[0].to_dict()

                # Get user profile if available
                user_profile = None
                if user_profiles and anomaly['username'] in user_profiles:
                    user_profile = user_profiles[anomaly['username']].get_behavior_summary()

                # Generate explanation
                explanation = self.explanation_generator.generate_comprehensive_explanation(
                    log_record, log_df, anomalies, user_profile
                )

                explained_anomaly = {
                    'original_anomaly': anomaly,
                    'explanation': explanation
                }

                explained_anomalies.append(explained_anomaly)

        report = {
            'generated_at': datetime.now(),
            'total_anomalies': len(explained_anomalies),
            'explained_anomalies': explained_anomalies,
            'summary': self._generate_summary(explained_anomalies)
        }

        self.reports.append(report)
        print(f"Report generated with explanations for {len(explained_anomalies)} anomalies")

        return report

    def _generate_summary(self, explained_anomalies):
        """
        Generate a summary of the explained anomalies
        """
        if not explained_anomalies:
            return {}

        # Count by severity
        severity_counts = Counter(a['original_anomaly']['severity'] for a in explained_anomalies)

        # Common explanation patterns
        rule_explanations = []
        for anomaly in explained_anomalies:
            rule_explanations.extend(anomaly['explanation']['rule_based']['explanations'])

        common_rules = Counter(rule_explanations)

        summary = {
            'by_severity': dict(severity_counts),
            'common_patterns': dict(common_rules.most_common(5)),
            'total_explained': len(explained_anomalies)
        }

        return summary


# Example usage
if __name__ == "__main__":
    import pandas as pd
    import numpy as np

    # Create sample data
    np.random.seed(42)
    dates = pd.date_range(start='2023-01-01', periods=200, freq='1H')

    sample_data = {
        'timestamp': [],
        'username': [],
        'ip_address': [],
        'event_type': []
    }

    usernames = ['alice', 'bob', 'charlie', 'diana'] * 50
    ip_addresses = (
        ['192.168.1.10'] * 80 +
        ['192.168.1.11'] * 60 +
        ['10.0.0.5'] * 40 +
        ['203.0.113.10'] * 20
    )[:200]

    event_types = (
        ['successful_login'] * 140 +
        ['failed_login'] * 40 +
        ['logout'] * 20
    )[:200]

    np.random.shuffle(usernames)
    np.random.shuffle(ip_addresses)
    np.random.shuffle(event_types)

    sample_data['timestamp'] = dates
    sample_data['username'] = usernames
    sample_data['ip_address'] = ip_addresses
    sample_data['event_type'] = event_types

    df = pd.DataFrame(sample_data)

    # Create sample anomalies
    sample_anomalies = [
        {
            'timestamp': df.iloc[0]['timestamp'],
            'username': df.iloc[0]['username'],
            'ip_address': df.iloc[0]['ip_address'],
            'severity': 'high',
            'anomaly_type': 'unusual_time',
            'details': 'Login at unusual time'
        },
        {
            'timestamp': df.iloc[1]['timestamp'],
            'username': df.iloc[1]['username'],
            'ip_address': df.iloc[1]['ip_address'],
            'severity': 'medium',
            'anomaly_type': 'location_change',
            'details': 'Login from new location'
        }
    ]

    # Test the XAI reporter
    xai_reporter = XAIAnomalyReporter()
    report = xai_reporter.generate_explained_report(df, sample_anomalies)

    print(f"Report Summary: {report['summary']}")

    # Print first explanation
    if report['explained_anomalies']:
        first_explanation = report['explained_anomalies'][0]['explanation']
        print(f"\nFirst explanation: {first_explanation}")