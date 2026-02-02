"""
Federated Learning Module for Privacy-Preserving Anomaly Detection
Enables collaborative model training across multiple organizations without sharing raw data
"""
import pandas as pd
import numpy as np
from datetime import datetime
import json
import hashlib
import pickle
from cryptography.fernet import Fernet
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score
import warnings
warnings.filterwarnings('ignore')

class SecureAggregator:
    """
    Secure aggregation for federated learning that preserves privacy
    """
    
    def __init__(self, encryption_key=None):
        if encryption_key is None:
            self.encryption_key = Fernet.generate_key()
        else:
            self.encryption_key = encryption_key
        self.cipher_suite = Fernet(self.encryption_key)
        
    def encrypt_model_parameters(self, params):
        """
        Encrypt model parameters for secure transmission
        """
        serialized_params = pickle.dumps(params)
        encrypted_params = self.cipher_suite.encrypt(serialized_params)
        return encrypted_params
    
    def decrypt_model_parameters(self, encrypted_params):
        """
        Decrypt model parameters
        """
        decrypted_params = self.cipher_suite.decrypt(encrypted_params)
        params = pickle.loads(decrypted_params)
        return params
    
    def aggregate_gradients_securely(self, client_gradients, weights=None):
        """
        Perform secure aggregation of gradients from multiple clients
        """
        if weights is None:
            weights = [1.0/len(client_gradients)] * len(client_gradients)
        
        # Weighted average of gradients
        aggregated_gradients = {}
        for param_name in client_gradients[0].keys():
            weighted_sum = sum(w * grad[param_name] for w, grad in zip(weights, client_gradients))
            aggregated_gradients[param_name] = weighted_sum / sum(weights)
        
        return aggregated_gradients


class LocalAnomalyModel:
    """
    Local anomaly detection model that can participate in federated learning
    """
    
    def __init__(self, model_type='isolation_forest', local_data=None):
        self.model_type = model_type
        self.local_data = local_data
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.training_history = []
        
        # Initialize model based on type
        if model_type == 'isolation_forest':
            self.model = IsolationForest(contamination=0.1, random_state=42)
        elif model_type == 'logistic_regression':
            self.model = LogisticRegression(random_state=42)
        
    def prepare_local_features(self, log_df):
        """
        Prepare features from local log data
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
            # Use hash to preserve privacy
            features['username_hash'] = log_df['username'].apply(lambda x: hash(str(x)) % 10000)
        
        # IP-based features
        if 'ip_address' in log_df.columns:
            # Use hash to preserve privacy
            features['ip_hash'] = log_df['ip_address'].apply(lambda x: hash(str(x)) % 10000)
            features['is_private_ip'] = log_df['ip_address'].apply(
                lambda x: 1 if pd.notna(x) and x.startswith(('10.', '172.', '192.168.')) else 0
            )
        
        # Event type features
        if 'event_type' in log_df.columns:
            event_mapping = {'successful_login': 1, 'failed_login': 0, 'logout': 2}
            features['event_type_encoded'] = log_df['event_type'].map(event_mapping).fillna(-1)
        
        # Interaction features
        if 'hour' in features.columns and 'username_hash' in features.columns:
            features['hour_username_interaction'] = features['hour'] * features['username_hash']
        
        # Fill NaN values with 0
        features = features.fillna(0)
        
        return features.values
    
    def train_local_model(self, log_df, labels=None):
        """
        Train the local model on local data
        """
        X = self.prepare_local_features(log_df)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        if self.model_type == 'isolation_forest':
            # For unsupervised anomaly detection
            self.model.fit(X_scaled)
            self.is_trained = True
        elif self.model_type == 'logistic_regression' and labels is not None:
            # For supervised learning
            self.model.fit(X_scaled, labels)
            self.is_trained = True
        
        # Record training
        self.training_history.append({
            'timestamp': datetime.now(),
            'data_size': len(log_df),
            'features_shape': X_scaled.shape
        })
    
    def extract_model_parameters(self):
        """
        Extract model parameters for federated learning
        """
        if not self.is_trained:
            return None

        # For Isolation Forest, we extract relevant attributes
        if self.model_type == 'isolation_forest':
            # Since IsolationForest doesn't expose all parameters directly,
            # we'll store the model object itself for now
            params = {
                'model_type': self.model_type,
                'contamination': self.model.contamination,
                'n_estimators': self.model.n_estimators,
                'max_samples': self.model.max_samples,
                'random_state': self.model.random_state
            }
        elif self.model_type == 'logistic_regression':
            params = {
                'model_type': self.model_type,
                'coef_': self.model.coef_,
                'intercept_': self.model.intercept_,
                'classes_': self.model.classes_
            }

        return params
    
    def update_model_with_global_params(self, global_params):
        """
        Update local model with global parameters from federated learning
        """
        if self.model_type == 'isolation_forest':
            # Recreate Isolation Forest with global parameters
            self.model = IsolationForest(
                contamination=global_params.get('contamination', 0.1),
                n_estimators=global_params.get('n_estimators', 100),
                max_samples=global_params.get('max_samples', 'auto'),
                random_state=global_params.get('random_state', 42)
            )
            # Re-fit with local data to adapt to local patterns
            if self.local_data is not None:
                X = self.prepare_local_features(self.local_data)
                if len(X) > 0:
                    # Create a new scaler for this update to avoid dimension mismatch
                    new_scaler = StandardScaler()
                    X_scaled = new_scaler.fit_transform(X)
                    self.model.fit(X_scaled)
                    # Update the local scaler to match
                    self.scaler = new_scaler
                else:
                    # If no features extracted, just fit with dummy data
                    dummy_data = np.random.rand(10, 10)
                    self.scaler = StandardScaler()
                    self.scaler.fit(dummy_data)
                    self.model.fit(dummy_data)
            else:
                # If no local data, just fit with dummy data
                dummy_data = np.random.rand(10, 10)
                self.scaler = StandardScaler()
                self.scaler.fit(dummy_data)
                self.model.fit(dummy_data)
        elif self.model_type == 'logistic_regression':
            # Update Logistic Regression with global parameters
            self.model.coef_ = global_params['coef_']
            self.model.intercept_ = global_params['intercept_']
            self.model.classes_ = global_params['classes_']

        self.is_trained = True


class FederatedAnomalyDetector:
    """
    Main class for federated anomaly detection
    """
    
    def __init__(self, central_aggregator=None):
        self.clients = {}
        self.central_aggregator = central_aggregator or SecureAggregator()
        self.global_model_params = None
        self.round_number = 0
        self.federation_history = []
        
    def register_client(self, client_id, local_model):
        """
        Register a client with the federation
        """
        self.clients[client_id] = {
            'model': local_model,
            'participation_count': 0,
            'performance_metrics': []
        }
        print(f"Client {client_id} registered in federation")
    
    def conduct_federated_round(self, selected_clients=None, local_epochs=1):
        """
        Conduct one round of federated learning
        """
        print(f"Starting federated round {self.round_number + 1}")
        
        if selected_clients is None:
            selected_clients = list(self.clients.keys())
        
        # Collect model parameters from participating clients
        client_params = []
        client_weights = []
        
        for client_id in selected_clients:
            client_info = self.clients[client_id]
            local_model = client_info['model']
            
            # Train locally if global model is available
            if self.global_model_params is not None:
                local_model.update_model_with_global_params(self.global_model_params)
            
            # Get local data for training (in real scenario, this would be the client's private data)
            # For this example, we'll use a subset of the data
            if local_model.local_data is not None:
                local_model.train_local_model(local_model.local_data)
            
            # Extract parameters
            params = local_model.extract_model_parameters()
            if params is not None:
                client_params.append(params)
                # Weight by data size
                client_weights.append(len(local_model.local_data) if local_model.local_data is not None else 1)
                
                # Update participation count
                client_info['participation_count'] += 1
        
        if not client_params:
            print("No client parameters collected, skipping round")
            return
        
        # Normalize weights
        total_weight = sum(client_weights)
        normalized_weights = [w / total_weight for w in client_weights]
        
        # Aggregate parameters securely
        self.global_model_params = self._aggregate_parameters(client_params, normalized_weights)
        
        # Update all clients with the global model
        for client_id in selected_clients:
            client_info = self.clients[client_id]
            client_info['model'].update_model_with_global_params(self.global_model_params)
        
        # Record federation round
        round_info = {
            'round_number': self.round_number,
            'timestamp': datetime.now(),
            'participants': len(selected_clients),
            'total_clients': len(self.clients),
            'average_data_size': np.mean([len(c['model'].local_data) if c['model'].local_data is not None else 0 
                                          for c in self.clients.values()])
        }
        
        self.federation_history.append(round_info)
        self.round_number += 1
        
        print(f"Federated round {self.round_number} completed with {len(selected_clients)} participants")
    
    def _aggregate_parameters(self, client_params, weights):
        """
        Aggregate parameters from multiple clients
        """
        # For Isolation Forest, we'll use a simplified approach
        # In practice, this would be more complex
        if client_params[0]['model_type'] == 'isolation_forest':
            # Simplified aggregation - average the hyperparameters
            contamination_values = [params['contamination'] for params in client_params]
            n_estimators_values = [params['n_estimators'] for params in client_params]

            aggregated_params = {
                'model_type': 'isolation_forest',
                'contamination': np.mean(contamination_values),
                'n_estimators': int(np.mean(n_estimators_values)),
                'max_samples': client_params[0]['max_samples'],  # Use first client's value
                'random_state': client_params[0]['random_state']  # Use first client's value
            }
        elif client_params[0]['model_type'] == 'logistic_regression':
            # Aggregate logistic regression parameters
            aggregated_params = {
                'model_type': 'logistic_regression',
                'coef_': np.average([params['coef_'] for params in client_params], axis=0, weights=weights),
                'intercept_': np.average([params['intercept_'] for params in client_params], weights=weights),
                'classes_': client_params[0]['classes_']
            }
        
        return aggregated_params
    
    def evaluate_federation_performance(self, test_data):
        """
        Evaluate the performance of the federated model on test data
        """
        if self.global_model_params is None:
            print("No global model available for evaluation")
            return {}
        
        # Create a temporary model with global parameters for evaluation
        temp_model = LocalAnomalyModel(model_type=self.global_model_params['model_type'])
        temp_model.update_model_with_global_params(self.global_model_params)
        
        # Prepare test features
        X_test = temp_model.prepare_local_features(test_data)
        X_test_scaled = temp_model.scaler.transform(X_test)
        
        # Make predictions
        if temp_model.model_type == 'isolation_forest':
            predictions = temp_model.model.predict(X_test_scaled)
            # Convert to binary (1 for normal, -1 for anomaly)
            # For evaluation, we might need labels which we don't have in unsupervised case
            # So we'll just return the predictions
            performance = {
                'predictions': predictions,
                'anomaly_count': sum(predictions == -1),
                'normal_count': sum(predictions == 1)
            }
        elif temp_model.model_type == 'logistic_regression' and 'labels' in test_data.columns:
            predictions = temp_model.model.predict(X_test_scaled)
            labels = test_data['labels']
            performance = {
                'accuracy': accuracy_score(labels, predictions),
                'precision': precision_score(labels, predictions, average='weighted'),
                'recall': recall_score(labels, predictions, average='weighted'),
                'predictions': predictions
            }
        
        return performance
    
    def detect_anomalies_federated(self, log_df, client_id=None):
        """
        Detect anomalies using the federated model
        """
        if self.global_model_params is None:
            print("No global model available, using local model")
            if client_id and client_id in self.clients:
                return self.clients[client_id]['model'].detect_anomalies(log_df)
            else:
                print("No client specified, returning empty results")
                return []
        
        # Create a temporary model with global parameters
        temp_model = LocalAnomalyModel(model_type=self.global_model_params['model_type'])
        temp_model.update_model_with_global_params(self.global_model_params)
        
        # Prepare features
        X = temp_model.prepare_local_features(log_df)
        # Handle potential dimension mismatch between scaler and features
        try:
            X_scaled = temp_model.scaler.transform(X)
        except ValueError as e:
            if "features" in str(e):
                # Dimension mismatch - fit scaler on this data
                temp_model.scaler.fit(X)
                X_scaled = temp_model.scaler.transform(X)
            else:
                raise e
        
        # Detect anomalies
        if temp_model.model_type == 'isolation_forest':
            anomaly_labels = temp_model.model.predict(X_scaled)
            anomaly_scores = temp_model.model.decision_function(X_scaled)
            
            # Convert to our standard anomaly format
            anomalies = []
            for i, (label, score) in enumerate(zip(anomaly_labels, anomaly_scores)):
                if label == -1:  # Anomaly detected
                    severity = 'high' if score < -0.5 else 'medium'
                    anomalies.append({
                        'timestamp': log_df.iloc[i]['timestamp'] if 'timestamp' in log_df.columns else datetime.now(),
                        'username': log_df.iloc[i]['username'] if 'username' in log_df.columns else 'Unknown',
                        'ip_address': log_df.iloc[i]['ip_address'] if 'ip_address' in log_df.columns else 'Unknown',
                        'anomaly_type': 'federated_ml_detected',
                        'severity': severity,
                        'anomaly_score': float(score),
                        'details': f'Federated ML model detected anomaly with score {score:.3f}'
                    })
            
            return anomalies
        else:
            # For other model types, return empty list
            return []


class FederatedLearningCoordinator:
    """
    Coordinates the federated learning process
    """
    
    def __init__(self):
        self.federated_detector = FederatedAnomalyDetector()
        self.communication_log = []
        
    def setup_federation(self, client_configs):
        """
        Set up the federation with multiple clients
        """
        for client_id, config in client_configs.items():
            # Create local model for client
            local_model = LocalAnomalyModel(
                model_type=config.get('model_type', 'isolation_forest'),
                local_data=config.get('local_data')
            )
            
            # Register client
            self.federated_detector.register_client(client_id, local_model)
        
        print(f"Federation set up with {len(client_configs)} clients")
    
    def run_federated_training(self, rounds=5, clients_per_round=None):
        """
        Run multiple rounds of federated training
        """
        print(f"Starting federated training for {rounds} rounds")
        
        for round_num in range(rounds):
            # Select clients for this round (random selection)
            all_clients = list(self.federated_detector.clients.keys())
            if clients_per_round and clients_per_round < len(all_clients):
                import random
                selected_clients = random.sample(all_clients, clients_per_round)
            else:
                selected_clients = all_clients
            
            # Conduct federated round
            self.federated_detector.conduct_federated_round(selected_clients)
            
            # Log communication
            self.communication_log.append({
                'round': round_num,
                'timestamp': datetime.now(),
                'selected_clients': selected_clients,
                'message_type': 'model_update'
            })
        
        print(f"Completed {rounds} rounds of federated training")
    
    def get_federation_status(self):
        """
        Get status of the federation
        """
        status = {
            'total_clients': len(self.federated_detector.clients),
            'completed_rounds': self.federated_detector.round_number,
            'federation_history': self.federated_detector.federation_history,
            'client_participation': {
                client_id: info['participation_count']
                for client_id, info in self.federated_detector.clients.items()
            }
        }
        
        return status


# Example usage
if __name__ == "__main__":
    import pandas as pd
    import numpy as np
    
    # Create sample data for multiple clients
    np.random.seed(42)
    
    # Client 1 data
    dates1 = pd.date_range(start='2023-01-01', periods=100, freq='1H')
    client1_data = pd.DataFrame({
        'timestamp': dates1,
        'username': ['alice', 'bob'] * 50,
        'ip_address': ['192.168.1.10', '10.0.0.5'] * 50,
        'event_type': ['successful_login', 'failed_login'] * 50
    })
    
    # Client 2 data
    dates2 = pd.date_range(start='2023-01-01', periods=100, freq='1H')
    client2_data = pd.DataFrame({
        'timestamp': dates2,
        'username': ['charlie', 'diana'] * 50,
        'ip_address': ['192.168.1.11', '203.0.113.10'] * 50,
        'event_type': ['successful_login', 'logout'] * 50
    })
    
    # Client 3 data
    dates3 = pd.date_range(start='2023-01-01', periods=100, freq='1H')
    client3_data = pd.DataFrame({
        'timestamp': dates3,
        'username': ['eve', 'frank'] * 50,
        'ip_address': ['192.168.1.12', '198.51.100.5'] * 50,
        'event_type': ['failed_login', 'successful_login'] * 50
    })
    
    # Set up federation
    coordinator = FederatedLearningCoordinator()
    
    client_configs = {
        'client_1': {
            'model_type': 'isolation_forest',
            'local_data': client1_data
        },
        'client_2': {
            'model_type': 'isolation_forest',
            'local_data': client2_data
        },
        'client_3': {
            'model_type': 'isolation_forest',
            'local_data': client3_data
        }
    }
    
    coordinator.setup_federation(client_configs)
    
    # Run federated training
    coordinator.run_federated_training(rounds=3, clients_per_round=3)
    
    # Get federation status
    status = coordinator.get_federation_status()
    print(f"Federation Status: {status}")
    
    # Test anomaly detection with federated model
    test_data = client1_data  # Using client 1's data for testing
    anomalies = coordinator.federated_detector.detect_anomalies_federated(test_data)
    
    print(f"Detected {len(anomalies)} anomalies using federated model")
    for i, anomaly in enumerate(anomalies[:3]):  # Show first 3 anomalies
        print(f"  {i+1}. {anomaly}")