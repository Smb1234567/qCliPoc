"""
Advanced Anomaly Detection Module with Graph-based Analysis
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from datetime import datetime, timedelta
import networkx as nx
import warnings
warnings.filterwarnings('ignore')

class GraphAnomalyDetector:
    """
    Graph-based anomaly detection using NetworkX
    """

    def __init__(self):
        self.graph = nx.Graph()
        self.node_features = {}
        self.edge_weights = {}

    def build_user_ip_graph(self, log_df):
        """
        Build a graph connecting users and IP addresses based on authentication events
        """
        self.graph.clear()

        for _, row in log_df.iterrows():
            user = row['username']
            ip = row['ip_address']

            # Add nodes if they don't exist
            if user not in self.graph.nodes:
                self.graph.add_node(user, node_type='user')
            if ip not in self.graph.nodes:
                self.graph.add_node(ip, node_type='ip')

            # Add edge between user and IP
            if self.graph.has_edge(user, ip):
                self.graph[user][ip]['weight'] += 1
            else:
                self.graph.add_edge(user, ip, weight=1)

        # Calculate graph features for each node
        for node in self.graph.nodes():
            # Calculate degree (number of connections)
            degree = self.graph.degree(node)

            # Calculate betweenness centrality (how often node appears on shortest paths)
            try:
                betweenness = nx.betweenness_centrality(self.graph)[node]
            except:
                betweenness = 0  # Handle disconnected components

            # Calculate closeness centrality (how close node is to all others)
            try:
                closeness = nx.closeness_centrality(self.graph)[node]
            except:
                closeness = 0  # Handle disconnected components

            # Calculate clustering coefficient (how connected neighbors are)
            clustering = nx.clustering(self.graph, node)

            self.node_features[node] = {
                'degree': degree,
                'betweenness': betweenness,
                'closeness': closeness,
                'clustering': clustering
            }

    def detect_graph_anomalies(self):
        """
        Detect anomalies based on graph structure and centrality measures
        """
        anomalies = []

        # Calculate statistics for centrality measures
        betweenness_vals = [self.node_features[node]['betweenness'] for node in self.graph.nodes()]
        closeness_vals = [self.node_features[node]['closeness'] for node in self.graph.nodes()]

        # Calculate mean and std for z-score calculation
        bet_mean = np.mean(betweenness_vals) if betweenness_vals else 0
        bet_std = np.std(betweenness_vals) if len(betweenness_vals) > 1 else 1
        clo_mean = np.mean(closeness_vals) if closeness_vals else 0
        clo_std = np.std(closeness_vals) if len(closeness_vals) > 1 else 1

        # Identify nodes with unusual centrality measures
        for node in self.graph.nodes():
            node_type = self.graph.nodes[node].get('node_type', 'unknown')

            # Calculate z-scores
            bet_z = (self.node_features[node]['betweenness'] - bet_mean) / bet_std if bet_std > 0 else 0
            clo_z = (self.node_features[node]['closeness'] - clo_mean) / clo_std if clo_std > 0 else 0

            # Flag as anomaly if z-score is too high
            if abs(bet_z) > 2.0 or abs(clo_z) > 2.0:
                severity = 'high' if abs(bet_z) > 3.0 or abs(clo_z) > 3.0 else 'medium'

                anomalies.append({
                    'node': node,
                    'node_type': node_type,
                    'betweenness_z_score': bet_z,
                    'closeness_z_score': clo_z,
                    'anomaly_type': 'graph_structure',
                    'severity': severity,
                    'details': f'{node_type} "{node}" has unusual centrality (bet_z: {bet_z:.2f}, clo_z: {clo_z:.2f})'
                })

        return anomalies


class SequentialPatternAnalyzer:
    """
    Analyzes sequential patterns in user behavior
    """

    def __init__(self):
        self.user_patterns = {}
        self.sequence_length = 5  # Number of previous events to consider

    def analyze_sequential_patterns(self, log_df):
        """
        Analyze sequential patterns for each user
        """
        anomalies = []

        for user in log_df['username'].unique():
            user_logs = log_df[log_df['username'] == user].sort_values('timestamp')

            if len(user_logs) < self.sequence_length:
                continue

            # Analyze patterns in the sequence
            for i in range(self.sequence_length, len(user_logs)):
                sequence = user_logs.iloc[i-self.sequence_length:i]
                current_event = user_logs.iloc[i]

                # Check for unusual time patterns
                time_diffs = [(sequence.iloc[j+1]['timestamp'] - sequence.iloc[j]['timestamp']).total_seconds()
                              for j in range(len(sequence)-1)]

                if time_diffs:
                    avg_time_diff = np.mean(time_diffs)
                    current_time_diff = (current_event['timestamp'] - sequence.iloc[-1]['timestamp']).total_seconds()

                    if avg_time_diff > 0 and abs(current_time_diff - avg_time_diff) > 3 * np.std(time_diffs):
                        anomalies.append({
                            'timestamp': current_event['timestamp'],
                            'username': current_event['username'],
                            'ip_address': current_event.get('ip_address', 'Unknown'),
                            'event_type': current_event.get('event_type', 'Unknown'),
                            'anomaly_type': 'sequential_timing',
                            'severity': 'medium',
                            'details': f'Unusual time gap in sequence for user {user}'
                        })

        return anomalies


class AdvancedAnomalyDetector:
    """
    Main class combining all advanced detection methods
    """

    def __init__(self):
        self.graph_detector = GraphAnomalyDetector()
        self.sequential_analyzer = SequentialPatternAnalyzer()

    def detect_advanced_anomalies(self, log_df):
        """
        Detect anomalies using multiple advanced methods
        """
        all_anomalies = []

        # 1. Graph-based anomalies
        print("Detecting graph-based anomalies...")
        self.graph_detector.build_user_ip_graph(log_df)
        graph_anomalies = self.graph_detector.detect_graph_anomalies()

        # Convert graph anomalies to standard format
        for anomaly in graph_anomalies:
            if anomaly['node_type'] == 'user':
                all_anomalies.append({
                    'timestamp': log_df[log_df['username'] == anomaly['node']].iloc[0]['timestamp'] if len(log_df[log_df['username'] == anomaly['node']]) > 0 else datetime.now(),
                    'username': anomaly['node'] if anomaly['node_type'] == 'user' else 'Unknown',
                    'ip_address': anomaly['node'] if anomaly['node_type'] == 'ip' else 'Unknown',
                    'anomaly_type': anomaly['anomaly_type'],
                    'severity': anomaly['severity'],
                    'method': 'graph_based',
                    'details': anomaly['details']
                })

        # 2. Sequential pattern anomalies
        print("Analyzing sequential patterns...")
        sequential_anomalies = self.sequential_analyzer.analyze_sequential_patterns(log_df)
        for anomaly in sequential_anomalies:
            anomaly['method'] = 'sequential_pattern'
            all_anomalies.append(anomaly)

        return all_anomalies


# Example usage
if __name__ == "__main__":
    # Create sample data for testing
    import pandas as pd
    import numpy as np

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

    # Test the advanced detector
    detector = AdvancedAnomalyDetector()
    anomalies = detector.detect_advanced_anomalies(df)

    print(f"Detected {len(anomalies)} anomalies using advanced methods:")
    for i, anomaly in enumerate(anomalies[:5]):
        print(f"{i+1}. {anomaly}")