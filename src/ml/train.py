import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix

def train_model(data_dir='data/processed', model_dir='data/models'):
    print("Loading Preprocessed Data...")
    X = joblib.load(os.path.join(data_dir, 'X.joblib'))
    y = joblib.load(os.path.join(data_dir, 'y.joblib'))
    le = joblib.load(os.path.join(data_dir, 'label_encoder.joblib'))
    tfidf = joblib.load(os.path.join(data_dir, 'tfidf_vectorizer.joblib'))
    feature_keys = joblib.load(os.path.join(data_dir, 'feature_keys.joblib'))

    # Split into Training and Testing sets (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"Training set size: {X_train.shape[0]}")
    print(f"Testing set size: {X_test.shape[0]}")

    print("\nTraining Random Forest Classifier...")
    # Using 100 trees and balanced class weights to handle any minor imbalance
    rf = RandomForestClassifier(
        n_estimators=100,           # 100 trees
        max_depth=20,               # Limiting depth to prevent extreme overfitting
        random_state=42,            # Seed for reprducing results
        n_jobs=-1,                  # Make use of all CPU cores
        class_weight='balanced'     # Tells the model that there might be imbalance in good and bad code
    )
    
    rf.fit(X_train, y_train)

    print("\nEvaluating Model Performance...")
    y_pred = rf.predict(X_test)
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    # Cross-validation for project robustness
    print("\nPerforming 5-Fold Cross-Validation (checking for overfitting)...")
    cv_scores = cross_val_score(rf, X, y, cv=5)
    print(f"Mean CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")

    print("\nFeature Importance Analysis...")
    # Combine manual feature names with TF-IDF token names
    tfidf_feature_names = tfidf.get_feature_names_out()
    all_feature_names = list(feature_keys) + list(tfidf_feature_names)
    
    importances = rf.feature_importances_
    indices = np.argsort(importances)[::-1]

    print("\nTop 20 Most Important Features (The AI's 'Rules'):")
    for i in range(20):
        idx = indices[i]
        importance = importances[idx]
        name = all_feature_names[idx]
        print(f"{i+1:2d}. {name:30s} : {importance:.4f}")

    # Save the Model
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)
        
    print(f"\nSaving Model to {model_dir}...")
    model_path = os.path.join(model_dir, 'random_forest_model.joblib')
    joblib.dump(rf, model_path)
    print(f"Model saved successfully at {model_path}")

if __name__ == "__main__":
    train_model()
