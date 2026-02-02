import pandas as pd
import numpy as np
import json
import yaml
from datetime import datetime
import re
from pathlib import Path


class LogIngestor:
    """
    A class to ingest and process authentication logs from various sources.
    Supports parsing common log formats and converting them to a standardized format.
    """

    def __init__(self, config_path="config.yaml"):
        """
        Initialize the LogIngestor with configuration settings.

        Args:
            config_path (str): Path to the configuration file
        """
        self.config = self.load_config(config_path)
        self.supported_formats = [
            'syslog',
            'json',
            'csv',
            'apache_common',
            'apache_combined'
        ]

    def load_config(self, config_path):
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            # Return default config if file doesn't exist
            return {
                'log_sources': [],
                'field_mappings': {},
                'time_format': '%Y-%m-%d %H:%M:%S'
            }

    def parse_syslog_format(self, log_line):
        """
        Parse syslog format authentication logs.

        Example format: Jan 15 10:30:15 hostname sshd[1234]: Failed password for invalid user hacker from 192.168.1.1 port 12345 ssh2
        """
        pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\[\d+\]:\s+(.*)'
        match = re.match(pattern, log_line)

        if match:
            timestamp_str, hostname, service, message = match.groups()

            # Convert timestamp to datetime object
            timestamp = datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
            # Assuming current year for the timestamp
            timestamp = timestamp.replace(year=datetime.now().year)

            # Extract IP address
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ip_match = re.search(ip_pattern, message)
            ip_address = ip_match.group(0) if ip_match else None

            # Determine event type
            event_type = 'unknown'
            if 'Failed' in message or 'Invalid' in message:
                event_type = 'failed_login'
            elif 'Accepted' in message:
                event_type = 'successful_login'
            elif 'Disconnected' in message or 'session closed' in message.lower():
                event_type = 'logout'

            # Extract username if present
            username_pattern = r'(?:for|user)\s+(\w+)'
            username_match = re.search(username_pattern, message)
            username = username_match.group(1) if username_match else None

            # Handle 'invalid user' case
            if 'invalid user' in message.lower():
                username = 'invalid'

            return {
                'timestamp': timestamp,
                'hostname': hostname,
                'service': service,
                'event_type': event_type,
                'username': username,
                'ip_address': ip_address,
                'message': message
            }

        return None

    def parse_json_format(self, log_line):
        """
        Parse JSON format authentication logs.
        """
        try:
            log_entry = json.loads(log_line)

            # Standardize field names based on config mappings
            standardized_entry = {}

            field_mappings = self.config.get('field_mappings', {})

            for standard_field, log_field in field_mappings.items():
                if log_field in log_entry:
                    standardized_entry[standard_field] = log_entry[log_field]
                else:
                    standardized_entry[standard_field] = None

            # Add default values if not mapped
            if 'timestamp' not in standardized_entry:
                standardized_entry['timestamp'] = log_entry.get('timestamp')
            if 'event_type' not in standardized_entry:
                standardized_entry['event_type'] = log_entry.get('event_type', 'unknown')
            if 'username' not in standardized_entry:
                standardized_entry['username'] = log_entry.get('username')
            if 'ip_address' not in standardized_entry:
                standardized_entry['ip_address'] = log_entry.get('ip_address')

            # Convert timestamp string to datetime if needed
            if standardized_entry['timestamp'] and isinstance(standardized_entry['timestamp'], str):
                time_format = self.config.get('time_format', '%Y-%m-%d %H:%M:%S')
                standardized_entry['timestamp'] = datetime.strptime(
                    standardized_entry['timestamp'], time_format
                )

            return standardized_entry

        except json.JSONDecodeError:
            return None

    def parse_csv_format(self, log_line, delimiter=','):
        """
        Parse CSV format authentication logs.
        """
        fields = log_line.strip().split(delimiter)

        # Assuming standard column order: timestamp, username, ip_address, event_type, message
        if len(fields) >= 5:
            try:
                timestamp = datetime.strptime(fields[0], self.config.get('time_format', '%Y-%m-%d %H:%M:%S'))

                return {
                    'timestamp': timestamp,
                    'username': fields[1],
                    'ip_address': fields[2],
                    'event_type': fields[3],
                    'message': fields[4]
                }
            except ValueError:
                # If timestamp parsing fails, return None
                return None

        return None

    def parse_apache_common_format(self, log_line):
        """
        Parse Apache common log format (with authentication extensions).
        """
        # Common log format: IP - USER [TIMESTAMP] "METHOD PATH PROTOCOL" STATUS SIZE
        pattern = r'(\S+) \S+ (\S+) \[(.+?)\] ".+?" (\d{3}) \S+ "(.*?)" "(.*?)"'
        match = re.match(pattern, log_line)

        if match:
            ip_address, username, timestamp_str, status_code, referrer, user_agent = match.groups()

            # Parse timestamp
            timestamp = datetime.strptime(timestamp_str.split()[0], '%d/%b/%Y:%H:%M:%S')

            # Determine event type based on status code
            event_type = 'access'
            if status_code.startswith('4') or status_code.startswith('5'):
                event_type = 'failed_access'
            elif status_code.startswith('2'):
                event_type = 'successful_access'

            return {
                'timestamp': timestamp,
                'username': username if username != '-' else None,
                'ip_address': ip_address,
                'event_type': event_type,
                'message': f'Status: {status_code}'
            }

        return None

    def parse_log_line(self, log_line, log_format='auto'):
        """
        Parse a single log line based on the specified format.

        Args:
            log_line (str): The log line to parse
            log_format (str): Format of the log ('syslog', 'json', 'csv', 'apache_common', 'apache_combined', 'auto')

        Returns:
            dict: Parsed log entry or None if parsing fails
        """
        if log_format == 'auto':
            # Try different formats until one succeeds
            for fmt in self.supported_formats:
                result = self.parse_log_line(log_line, fmt)
                if result:
                    return result
            return None

        if log_format == 'syslog':
            return self.parse_syslog_format(log_line)
        elif log_format == 'json':
            return self.parse_json_format(log_line)
        elif log_format == 'csv':
            return self.parse_csv_format(log_line)
        elif log_format in ['apache_common', 'apache_combined']:
            return self.parse_apache_common_format(log_line)
        else:
            raise ValueError(f"Unsupported log format: {log_format}")

    def read_log_file(self, file_path, log_format='auto'):
        """
        Read and parse an entire log file.

        Args:
            file_path (str): Path to the log file
            log_format (str): Format of the log file

        Returns:
            pd.DataFrame: DataFrame containing parsed log entries
        """
        parsed_logs = []

        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                parsed_entry = self.parse_log_line(line, log_format)
                if parsed_entry:
                    # Skip entries with None username or ip_address
                    if parsed_entry['username'] is not None and parsed_entry['ip_address'] is not None:
                        parsed_logs.append(parsed_entry)
                else:
                    print(f"Warning: Could not parse line {line_num}: {line[:100]}...")

        return pd.DataFrame(parsed_logs)

    def read_multiple_log_files(self, file_paths, log_format='auto'):
        """
        Read and parse multiple log files.

        Args:
            file_paths (list): List of paths to log files
            log_format (str): Format of the log files

        Returns:
            pd.DataFrame: DataFrame containing parsed log entries from all files
        """
        all_logs = []

        for file_path in file_paths:
            df = self.read_log_file(file_path, log_format)
            all_logs.append(df)

        if all_logs:
            combined_df = pd.concat(all_logs, ignore_index=True)
            # Sort by timestamp
            if 'timestamp' in combined_df.columns:
                combined_df = combined_df.sort_values('timestamp').reset_index(drop=True)
            return combined_df
        else:
            return pd.DataFrame()

    def save_parsed_logs(self, df, output_path):
        """
        Save parsed logs to a file in CSV format.

        Args:
            df (pd.DataFrame): DataFrame containing parsed logs
            output_path (str): Path to save the output file
        """
        df.to_csv(output_path, index=False)


# Example usage and testing
if __name__ == "__main__":
    # Create sample log file for testing
    sample_logs = [
        'Jan 15 10:30:15 server1 sshd[1234]: Failed password for invalid user hacker from 192.168.1.100 port 12345 ssh2',
        'Jan 15 10:31:22 server1 sshd[1235]: Accepted password for admin from 10.0.0.50 port 54321 ssh2',
        'Jan 15 10:45:30 server1 sshd[1236]: Received disconnect from 10.0.0.50: 11: disconnected by user',
        '{"timestamp": "2023-01-15 11:00:00", "username": "john_doe", "ip_address": "192.168.1.5", "event_type": "login", "success": true}',
        '192.168.1.10,-,john_doe,successful_login,"User logged in successfully"'
    ]

    # Write sample logs to a file
    with open('sample_auth.log', 'w') as f:
        for log in sample_logs:
            f.write(log + '\n')

    # Test the log ingestor
    ingestor = LogIngestor()
    df = ingestor.read_log_file('sample_auth.log')

    print("Parsed logs:")
    print(df)

    # Clean up sample file
    import os
    os.remove('sample_auth.log')