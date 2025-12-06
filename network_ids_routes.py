"""
Flask routes for Network-based AI-IDS
Provides API endpoints for model training, prediction, and monitoring
"""

from flask import Blueprint, request, jsonify, send_file
import os
import json
from datetime import datetime
import logging

try:
    from network_ids_module import get_network_ids, NetworkIDS
    NETWORK_IDS_AVAILABLE = True
except ImportError as e:
    NETWORK_IDS_AVAILABLE = False
    logging.warning(f"Network IDS module not available: {e}")

logger = logging.getLogger(__name__)

# Create Blueprint for network IDS routes
network_ids_bp = Blueprint('network_ids', __name__, url_prefix='/api/network-ids')

@network_ids_bp.route('/status', methods=['GET'])
def network_ids_status():
    """Get Network IDS status and statistics"""
    if not NETWORK_IDS_AVAILABLE:
        return jsonify({
            'available': False,
            'message': 'Network IDS module not available'
        }), 503
    
    try:
        network_ids = get_network_ids()
        stats = network_ids.get_traffic_statistics()
        
        return jsonify({
            'available': True,
            'is_trained': network_ids.is_trained,
            'model_type': network_ids.model_type,
            'metrics': network_ids.metrics if network_ids.is_trained else {},
            'statistics': stats
        })
    except Exception as e:
        logger.error(f"Error getting network IDS status: {e}")
        return jsonify({'error': str(e)}), 500

@network_ids_bp.route('/train', methods=['POST'])
def train_model():
    """Train Network IDS model"""
    if not NETWORK_IDS_AVAILABLE:
        return jsonify({'error': 'Network IDS module not available'}), 503
    
    try:
        data = request.get_json()
        dataset_path = data.get('dataset_path')
        dataset_type = data.get('dataset_type', 'nsl-kdd')  # nsl-kdd, unsw-nb15, iot-23
        model_type = data.get('model_type', 'random_forest')  # random_forest or dnn
        test_size = data.get('test_size', 0.2)
        
        if not dataset_path or not os.path.exists(dataset_path):
            return jsonify({'error': 'Dataset file not found'}), 400
        
        # Initialize Network IDS with specified model type
        network_ids = NetworkIDS(model_type=model_type)
        
        # Load dataset
        logger.info(f"Loading dataset: {dataset_type}")
        X, y, df = network_ids.load_dataset(dataset_path, dataset_type)
        
        # Train model
        logger.info("Training model...")
        metrics = network_ids.train(X, y, test_size=test_size)
        
        # Save model
        model_dir = 'models/network_ids'
        os.makedirs(model_dir, exist_ok=True)
        model_path = os.path.join(model_dir, f'{model_type}_model.pkl' if model_type == 'random_forest' else f'{model_type}_model.h5')
        network_ids.save_model(model_path)
        
        return jsonify({
            'success': True,
            'message': 'Model trained successfully',
            'metrics': metrics,
            'model_path': model_path
        })
        
    except Exception as e:
        logger.error(f"Error training model: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@network_ids_bp.route('/predict', methods=['POST'])
def predict_traffic():
    """Predict if network traffic is normal or attack"""
    if not NETWORK_IDS_AVAILABLE:
        return jsonify({'error': 'Network IDS module not available'}), 503
    
    try:
        data = request.get_json()
        traffic_features = data.get('features')
        
        if not traffic_features:
            return jsonify({'error': 'Traffic features required'}), 400
        
        network_ids = get_network_ids()
        
        if not network_ids.is_trained:
            return jsonify({'error': 'Model not trained. Please train the model first.'}), 400
        
        # Analyze traffic
        result = network_ids.analyze_network_traffic(traffic_features)
        
        return jsonify({
            'success': True,
            'result': result
        })
        
    except Exception as e:
        logger.error(f"Error predicting traffic: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@network_ids_bp.route('/load-model', methods=['POST'])
def load_model():
    """Load a pre-trained model"""
    if not NETWORK_IDS_AVAILABLE:
        return jsonify({'error': 'Network IDS module not available'}), 503
    
    try:
        data = request.get_json()
        model_path = data.get('model_path')
        
        if not model_path or not os.path.exists(model_path):
            return jsonify({'error': 'Model file not found'}), 400
        
        network_ids = get_network_ids()
        network_ids.load_model(model_path)
        
        return jsonify({
            'success': True,
            'message': 'Model loaded successfully',
            'metrics': network_ids.metrics,
            'model_type': network_ids.model_type
        })
        
    except Exception as e:
        logger.error(f"Error loading model: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@network_ids_bp.route('/statistics', methods=['GET'])
def get_statistics():
    """Get traffic statistics"""
    if not NETWORK_IDS_AVAILABLE:
        return jsonify({'error': 'Network IDS module not available'}), 503
    
    try:
        network_ids = get_network_ids()
        stats = network_ids.get_traffic_statistics()
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@network_ids_bp.route('/datasets', methods=['GET'])
def list_datasets():
    """List available datasets and their locations"""
    datasets_dir = 'datasets'
    available_datasets = []
    
    if os.path.exists(datasets_dir):
        for file in os.listdir(datasets_dir):
            file_path = os.path.join(datasets_dir, file)
            if os.path.isfile(file_path) and (file.endswith('.csv') or file.endswith('.json')):
                # Try to detect dataset type
                dataset_type = 'unknown'
                if 'kdd' in file.lower() or 'nsl' in file.lower():
                    dataset_type = 'nsl-kdd'
                elif 'unsw' in file.lower() or 'nb15' in file.lower():
                    dataset_type = 'unsw-nb15'
                elif 'iot' in file.lower() or 'iot23' in file.lower():
                    dataset_type = 'iot-23'
                
                available_datasets.append({
                    'filename': file,
                    'path': file_path,
                    'type': dataset_type,
                    'size': os.path.getsize(file_path)
                })
    
    return jsonify({
        'success': True,
        'datasets': available_datasets,
        'supported_types': ['nsl-kdd', 'unsw-nb15', 'iot-23']
    })

