#!/usr/bin/env python3
"""
Training Script for Network-based AI-IDS
Example script to train models on IoT security datasets
"""

import os
import sys
import argparse
from network_ids_module import NetworkIDS

def main():
    parser = argparse.ArgumentParser(description='Train Network IDS Model')
    parser.add_argument('--dataset', type=str, required=True, help='Path to dataset file')
    parser.add_argument('--dataset-type', type=str, default='nsl-kdd', 
                       choices=['nsl-kdd', 'unsw-nb15', 'iot-23'],
                       help='Type of dataset')
    parser.add_argument('--model-type', type=str, default='random_forest',
                       choices=['random_forest', 'dnn'],
                       help='Type of model to train')
    parser.add_argument('--test-size', type=float, default=0.2,
                       help='Proportion of data for testing (0.0-1.0)')
    parser.add_argument('--output', type=str, default=None,
                       help='Output path for trained model')
    
    args = parser.parse_args()
    
    # Validate dataset file
    if not os.path.exists(args.dataset):
        print(f"Error: Dataset file not found: {args.dataset}")
        sys.exit(1)
    
    print("=" * 60)
    print("Network IDS Model Training")
    print("=" * 60)
    print(f"Dataset: {args.dataset}")
    print(f"Dataset Type: {args.dataset_type}")
    print(f"Model Type: {args.model_type}")
    print(f"Test Size: {args.test_size}")
    print("=" * 60)
    print()
    
    try:
        # Initialize Network IDS
        print("Initializing Network IDS...")
        ids = NetworkIDS(model_type=args.model_type)
        
        # Load dataset
        print(f"Loading dataset: {args.dataset_type}...")
        X, y, df = ids.load_dataset(args.dataset, args.dataset_type)
        print(f"Loaded {len(X)} samples with {len(X.columns)} features")
        print(f"Normal samples: {(y == 0).sum()}, Attack samples: {(y == 1).sum()}")
        print()
        
        # Train model
        print("Training model...")
        print("This may take several minutes...")
        metrics = ids.train(X, y, test_size=args.test_size)
        print()
        
        # Display results
        print("=" * 60)
        print("Training Results")
        print("=" * 60)
        print(f"Accuracy:  {metrics['accuracy']:.4f}")
        print(f"Precision: {metrics['precision']:.4f}")
        print(f"Recall:    {metrics['recall']:.4f}")
        print(f"F1-Score:  {metrics['f1_score']:.4f}")
        print("=" * 60)
        print()
        
        # Save model
        if args.output:
            output_path = args.output
        else:
            model_dir = 'models/network_ids'
            os.makedirs(model_dir, exist_ok=True)
            ext = '.pkl' if args.model_type == 'random_forest' else '.h5'
            output_path = os.path.join(model_dir, f'{args.model_type}_model{ext}')
        
        print(f"Saving model to: {output_path}")
        ids.save_model(output_path)
        print("Model saved successfully!")
        print()
        print("You can now use this model for real-time traffic analysis.")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()

