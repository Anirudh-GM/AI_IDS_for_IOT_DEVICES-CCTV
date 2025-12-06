"""
Network-based AI-IDS Module for IoT Networks
Implements ML models for network traffic intrusion detection
Supports: Random Forest, Deep Neural Networks
Datasets: NSL-KDD, UNSW-NB15, IoT-23
"""

import numpy as np
import pandas as pd
import pickle
import os
from datetime import datetime
import logging
from collections import deque
import json

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logging.warning("Scikit-learn not available. ML features will be limited.")

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import Dense, Dropout, LSTM, Conv1D, MaxPooling1D, Flatten
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    logging.warning("TensorFlow not available. Deep learning features will be limited.")

logger = logging.getLogger(__name__)

class NetworkIDS:
    """Network-based Intrusion Detection System for IoT"""
    
    def __init__(self, model_type='random_forest'):
        """
        Initialize Network IDS
        Args:
            model_type: 'random_forest' or 'dnn' (Deep Neural Network)
        """
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.is_trained = False
        self.feature_names = []
        self.traffic_history = deque(maxlen=1000)  # Store recent traffic for analysis
        
        # Performance metrics
        self.metrics = {
            'accuracy': 0.0,
            'precision': 0.0,
            'recall': 0.0,
            'f1_score': 0.0
        }
        
    def load_dataset(self, dataset_path, dataset_type='nsl-kdd'):
        """
        Load and preprocess IoT security dataset
        Supported: NSL-KDD, UNSW-NB15, IoT-23
        """
        try:
            logger.info(f"Loading dataset: {dataset_type} from {dataset_path}")
            
            if dataset_type.lower() == 'nsl-kdd':
                return self._load_nsl_kdd(dataset_path)
            elif dataset_type.lower() == 'unsw-nb15':
                return self._load_unsw_nb15(dataset_path)
            elif dataset_type.lower() == 'iot-23':
                return self._load_iot23(dataset_path)
            else:
                raise ValueError(f"Unsupported dataset type: {dataset_type}")
                
        except Exception as e:
            logger.error(f"Error loading dataset: {e}")
            raise
    
    def _load_nsl_kdd(self, file_path):
        """Load NSL-KDD dataset"""
        # NSL-KDD column names
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack_type'
        ]
        
        df = pd.read_csv(file_path, names=columns)
        
        # Encode categorical features
        categorical_cols = ['protocol_type', 'service', 'flag']
        for col in categorical_cols:
            if col in df.columns:
                df[col] = pd.Categorical(df[col]).codes
        
        # Separate features and labels
        X = df.drop('attack_type', axis=1)
        y = df['attack_type']
        
        # Binary classification: Normal vs Attack
        y_binary = y.apply(lambda x: 0 if x == 'normal' else 1)
        
        return X, y_binary, df
    
    def _load_unsw_nb15(self, file_path):
        """Load UNSW-NB15 dataset"""
        df = pd.read_csv(file_path)
        
        # UNSW-NB15 has different structure
        # Extract features (exclude label columns)
        label_cols = ['label', 'attack_cat']
        feature_cols = [col for col in df.columns if col not in label_cols]
        
        X = df[feature_cols]
        
        # Handle categorical features
        categorical_cols = X.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            X[col] = pd.Categorical(X[col]).codes
        
        # Binary classification
        y_binary = df['label'] if 'label' in df.columns else df['attack_cat'].apply(lambda x: 0 if x == 'Normal' else 1)
        
        return X, y_binary, df
    
    def _load_iot23(self, file_path):
        """Load IoT-23 dataset"""
        # IoT-23 is typically in JSON or CSV format
        if file_path.endswith('.json'):
            df = pd.read_json(file_path)
        else:
            df = pd.read_csv(file_path)
        
        # IoT-23 structure varies, adapt as needed
        # This is a placeholder - adjust based on actual IoT-23 format
        label_col = 'label' if 'label' in df.columns else 'malicious'
        
        X = df.drop(label_col, axis=1)
        y_binary = df[label_col].apply(lambda x: 0 if x in ['normal', 'Benign'] else 1)
        
        return X, y_binary, df
    
    def preprocess_data(self, X, y=None):
        """Preprocess features: normalization, handling missing values"""
        # Handle missing values
        X = X.fillna(0)
        
        # Normalize features
        if y is None:
            # For prediction, use existing scaler
            X_scaled = self.scaler.transform(X)
        else:
            # For training, fit scaler
            X_scaled = self.scaler.fit_transform(X)
            self.feature_names = list(X.columns)
        
        return X_scaled
    
    def train_random_forest(self, X_train, y_train, n_estimators=100, max_depth=20):
        """Train Random Forest classifier"""
        if not SKLEARN_AVAILABLE:
            raise ImportError("Scikit-learn is required for Random Forest")
        
        logger.info("Training Random Forest model...")
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=42,
            n_jobs=-1,
            verbose=1
        )
        
        self.model.fit(X_train, y_train)
        self.is_trained = True
        logger.info("Random Forest model trained successfully")
    
    def train_dnn(self, X_train, y_train, epochs=50, batch_size=32):
        """Train Deep Neural Network"""
        if not TENSORFLOW_AVAILABLE:
            raise ImportError("TensorFlow is required for DNN")
        
        logger.info("Training Deep Neural Network...")
        
        input_dim = X_train.shape[1]
        
        self.model = Sequential([
            Dense(128, activation='relu', input_dim=input_dim),
            Dropout(0.3),
            Dense(64, activation='relu'),
            Dropout(0.3),
            Dense(32, activation='relu'),
            Dropout(0.2),
            Dense(1, activation='sigmoid')  # Binary classification
        ])
        
        self.model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        # Train model
        self.model.fit(
            X_train, y_train,
            epochs=epochs,
            batch_size=batch_size,
            verbose=1,
            validation_split=0.2
        )
        
        self.is_trained = True
        logger.info("Deep Neural Network trained successfully")
    
    def train(self, X, y, test_size=0.2):
        """
        Train the IDS model
        Args:
            X: Feature matrix
            y: Labels (0=normal, 1=attack)
            test_size: Proportion of data for testing
        """
        # Preprocess data
        X_processed = self.preprocess_data(X, y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_processed, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Train model based on type
        if self.model_type == 'random_forest':
            self.train_random_forest(X_train, y_train)
        elif self.model_type == 'dnn':
            self.train_dnn(X_train, y_train)
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
        
        # Evaluate on test set
        y_pred = self.predict(X_test)
        self.evaluate(y_test, y_pred)
        
        return self.metrics
    
    def predict(self, X):
        """Predict if traffic is normal (0) or attack (1)"""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        X_processed = self.preprocess_data(X)
        
        if self.model_type == 'random_forest':
            predictions = self.model.predict(X_processed)
        else:  # DNN
            predictions = (self.model.predict(X_processed) > 0.5).astype(int).flatten()
        
        return predictions
    
    def predict_proba(self, X):
        """Get prediction probabilities"""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        
        X_processed = self.preprocess_data(X)
        
        if self.model_type == 'random_forest':
            probabilities = self.model.predict_proba(X_processed)
        else:  # DNN
            probabilities = self.model.predict(X_processed)
        
        return probabilities
    
    def evaluate(self, y_true, y_pred):
        """Calculate performance metrics"""
        self.metrics['accuracy'] = accuracy_score(y_true, y_pred)
        self.metrics['precision'] = precision_score(y_true, y_pred, zero_division=0)
        self.metrics['recall'] = recall_score(y_true, y_pred, zero_division=0)
        self.metrics['f1_score'] = f1_score(y_true, y_pred, zero_division=0)
        
        logger.info(f"Model Performance:")
        logger.info(f"  Accuracy: {self.metrics['accuracy']:.4f}")
        logger.info(f"  Precision: {self.metrics['precision']:.4f}")
        logger.info(f"  Recall: {self.metrics['recall']:.4f}")
        logger.info(f"  F1-Score: {self.metrics['f1_score']:.4f}")
        
        return self.metrics
    
    def analyze_network_traffic(self, traffic_features):
        """
        Analyze network traffic in real-time
        Args:
            traffic_features: Dictionary or DataFrame with network traffic features
        """
        if not self.is_trained:
            return {
                'prediction': 'unknown',
                'confidence': 0.0,
                'message': 'Model not trained'
            }
        
        # Convert to DataFrame if dict
        if isinstance(traffic_features, dict):
            df = pd.DataFrame([traffic_features])
        else:
            df = traffic_features
        
        # Ensure feature order matches training
        if self.feature_names:
            df = df.reindex(columns=self.feature_names, fill_value=0)
        
        # Predict
        prediction = self.predict(df)
        probabilities = self.predict_proba(df)
        
        result = {
            'prediction': 'attack' if prediction[0] == 1 else 'normal',
            'confidence': float(probabilities[0][1] if prediction[0] == 1 else probabilities[0][0]),
            'timestamp': datetime.now().isoformat()
        }
        
        # Store in history
        self.traffic_history.append({
            **result,
            'features': traffic_features
        })
        
        return result
    
    def save_model(self, filepath):
        """Save trained model to file"""
        model_data = {
            'model_type': self.model_type,
            'feature_names': self.feature_names,
            'metrics': self.metrics,
            'is_trained': self.is_trained
        }
        
        # Save model
        if self.model_type == 'random_forest':
            with open(filepath, 'wb') as f:
                pickle.dump(self.model, f)
        else:  # DNN
            self.model.save(filepath)
        
        # Save scaler and metadata
        scaler_path = filepath.replace('.pkl', '_scaler.pkl').replace('.h5', '_scaler.pkl')
        metadata_path = filepath.replace('.pkl', '_metadata.json').replace('.h5', '_metadata.json')
        
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        
        with open(metadata_path, 'w') as f:
            json.dump(model_data, f, indent=2)
        
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath):
        """Load trained model from file"""
        metadata_path = filepath.replace('.pkl', '_metadata.json').replace('.h5', '_metadata.json')
        scaler_path = filepath.replace('.pkl', '_scaler.pkl').replace('.h5', '_scaler.pkl')
        
        # Load metadata
        with open(metadata_path, 'r') as f:
            model_data = json.load(f)
        
        self.model_type = model_data['model_type']
        self.feature_names = model_data['feature_names']
        self.metrics = model_data['metrics']
        self.is_trained = model_data['is_trained']
        
        # Load scaler
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        
        # Load model
        if self.model_type == 'random_forest':
            with open(filepath, 'rb') as f:
                self.model = pickle.load(f)
        else:  # DNN
            self.model = keras.models.load_model(filepath)
        
        logger.info(f"Model loaded from {filepath}")
    
    def get_traffic_statistics(self):
        """Get statistics about analyzed traffic"""
        if not self.traffic_history:
            return {
                'total_packets': 0,
                'normal_packets': 0,
                'attack_packets': 0,
                'attack_rate': 0.0
            }
        
        total = len(self.traffic_history)
        attacks = sum(1 for t in self.traffic_history if t['prediction'] == 'attack')
        
        return {
            'total_packets': total,
            'normal_packets': total - attacks,
            'attack_packets': attacks,
            'attack_rate': (attacks / total * 100) if total > 0 else 0.0,
            'recent_attacks': [t for t in list(self.traffic_history)[-10:] if t['prediction'] == 'attack']
        }


# Global instance
_network_ids = None

def get_network_ids(model_type='random_forest'):
    """Get or create Network IDS instance"""
    global _network_ids
    if _network_ids is None:
        _network_ids = NetworkIDS(model_type=model_type)
        logger.info(f"Network IDS initialized with {model_type} model")
    return _network_ids

