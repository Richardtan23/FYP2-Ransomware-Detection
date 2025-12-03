# evaluate_fusion.py
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, f1_score, accuracy_score, precision_score, recall_score

def evaluate_fusion_performance():
    """
    Simulate fusion performance by creating paired predictions
    This assumes you can map between static and behavioral samples
    """
    print("=== FUSION ENGINE PERFORMANCE EVALUATION ===")
    
    # Load your model results (you'll need to adapt this)
    static_results = {
        'probs': [0.8, 0.9, 0.1, 0.95, 0.05],  # Your static model probabilities
        'true_labels': [1, 1, 0, 1, 0]          # True labels
    }
    
    behavioral_results = {
        'probs': [0.85, 0.88, 0.15, 0.92, 0.08],  # Your behavioral model probabilities  
        'true_labels': [1, 1, 0, 1, 0]            # Should match static samples
    }
    
    # Your fusion weights
    STATIC_WEIGHT = 0.6
    BEHAVIORAL_WEIGHT = 0.4
    FUSION_THRESHOLD = 0.5
    
    # Calculate fused probabilities
    fused_probs = []
    for s_prob, b_prob in zip(static_results['probs'], behavioral_results['probs']):
        fused_prob = (s_prob * STATIC_WEIGHT) + (b_prob * BEHAVIORAL_WEIGHT)
        fused_probs.append(fused_prob)
    
    # Get predictions
    fused_preds = [1 if prob >= FUSION_THRESHOLD else 0 for prob in fused_probs]
    true_labels = static_results['true_labels']  # Should be same for both
    
    # Calculate metrics
    accuracy = accuracy_score(true_labels, fused_preds)
    precision = precision_score(true_labels, fused_preds)
    recall = recall_score(true_labels, fused_preds)
    f1 = f1_score(true_labels, fused_preds)
    
    print(f"Fusion Accuracy: {accuracy:.4f}")
    print(f"Fusion Precision: {precision:.4f}")
    print(f"Fusion Recall: {recall:.4f}")
    print(f"Fusion F1 Score: {f1:.4f}")
    
    print("\nFusion Classification Report:")
    print(classification_report(true_labels, fused_preds, target_names=['Benign', 'Malicious']))
    
    return {
        'fused_probs': fused_probs,
        'fused_preds': fused_preds,
        'metrics': {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1
        }
    }

if __name__ == "__main__":
    evaluate_fusion_performance()