import csv
import os
import sys
import numpy as np
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from scipy.sparse import hstack

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))
from src.ml.feature_extractor import FeatureExtractor

def preprocess_data(csv_path, output_dir='data/processed'):
    print(f"Loading data from {csv_path}...")
    
    code_samples = []
    labels = []
    
    # Load and Flatten Data
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Vulnerable Sample
            code_samples.append(row['vulnerable_code'])
            labels.append(row['vulnerability_type'])
            
            # Fixed (Safe) Sample
            code_samples.append(row['fixed_code'])
            labels.append('Safe')

    print(f"Total samples to process: {len(code_samples)}")

    # Extract Manual Features
    extractor = FeatureExtractor()
    manual_features = []
    
    # Order of features for the matrix
    feature_keys = [
        'num_tokens', 'num_strings', 'num_keywords', 
        'has_sql_keyword', 'has_command_keyword', 'has_xss_keyword',
        'has_string_concat', 'has_direct_exec', 'has_inline_script',
        'sql_and_concat_same_line'
    ]

    print("Extracting manual features...")
    for i, code in enumerate(code_samples):
        feats = extractor.extract_features(code)
        
        # Convert dict to numerical list in fixed order
        vector = [feats.get(k, 0) for k in feature_keys]
        manual_features.append(vector)
        
        # Shows status every 5000 samples
        if (i + 1) % 5000 == 0:
            print(f"  Processed {i + 1}/{len(code_samples)} samples...")

    manual_features_np = np.array(manual_features)         # Convert to numpy array

    # Textual Features (TF-IDF)
    print("Generating TF-IDF features...")
    # We use a small max_features to keep the model lightweight
    tfidf = TfidfVectorizer(max_features=1000, token_pattern=r'[a-zA-Z_][a-zA-Z0-9_]*|[^\w\s]')
    tfidf_features = tfidf.fit_transform(code_samples)

    # Combine Features
    print("Combining features...")
    X = hstack([manual_features_np, tfidf_features])        # Joins the matrices column wise
    
    # Encode Labels
    le = LabelEncoder()                 # Coverts labels (text) into numbers
    y = le.fit_transform(labels)
    
    # Save Everything
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    print(f"Saving processed data to {output_dir}...")
    joblib.dump(X, os.path.join(output_dir, 'X.joblib'))
    joblib.dump(y, os.path.join(output_dir, 'y.joblib'))
    joblib.dump(le, os.path.join(output_dir, 'label_encoder.joblib'))
    joblib.dump(tfidf, os.path.join(output_dir, 'tfidf_vectorizer.joblib'))
    joblib.dump(feature_keys, os.path.join(output_dir, 'feature_keys.joblib'))
    
    print(f"\nFinal Feature Matrix Shape: {X.shape}")
    print("Classes found:", le.classes_)

if __name__ == "__main__":
    csv_file = 'datasets/cleaned_file1.csv'
    if os.path.exists(csv_file):
        preprocess_data(csv_file)
    else:
        print(f"Error: Could not find {csv_file}")
