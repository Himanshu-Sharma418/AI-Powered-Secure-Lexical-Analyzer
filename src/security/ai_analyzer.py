import os
import sys
import joblib
import numpy as np
from scipy.sparse import hstack

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))
from src.ml.feature_extractor import FeatureExtractor

class AIAnalyzer:
    """Exclusive AI-driven vulnerability detector using Random Forest"""
    
    def __init__(self, model_dir='data/models', processed_dir='data/processed'):
        # Load the model and all associated metadata
        try:
            self.model = joblib.load(os.path.join(model_dir, 'random_forest_model.joblib'))
            self.le = joblib.load(os.path.join(processed_dir, 'label_encoder.joblib'))
            self.tfidf = joblib.load(os.path.join(processed_dir, 'tfidf_vectorizer.joblib'))
            self.feature_keys = joblib.load(os.path.join(processed_dir, 'feature_keys.joblib'))
            self.extractor = FeatureExtractor()
            self.initialized = True
        except Exception as e:
            print(f"Error loading AI model: {e}")
            self.initialized = False

    def _get_features(self, snippet):
        """Transform a code snippet into the exact feature format the model expects"""
        # Manual features
        feats = self.extractor.extract_features(snippet)
        manual_vector = np.array([[feats.get(k, 0) for k in self.feature_keys]])
        
        # TF-IDF features
        tfidf_vector = self.tfidf.transform([snippet])
        
        # Combine
        return hstack([manual_vector, tfidf_vector])

    def analyze(self, code, window_size=10, step_size=5):
        """
        Analyzes code using a sliding window to detect 'vulnerable parts'.
        Returns a list of detections with line numbers and confidence scores.
        """
        if not self.initialized:
            return []

        lines = code.split('\n')
        total_lines = len(lines)
        detections = []

        # If code is shorter than window, analyze it all at once
        if total_lines <= window_size:
            windows = [(1, total_lines, code)]
        else:
            # Create overlapping windows
            windows = []
            for i in range(0, total_lines, step_size):
                end = min(i + window_size, total_lines)
                snippet = '\n'.join(lines[i:end])
                windows.append((i + 1, end, snippet))
                if end == total_lines:
                    break

        for start_line, end_line, snippet in windows:
            # Skip empty snippets
            if not snippet.strip():
                continue

            # Get features and predict
            X = self._get_features(snippet)
            probabilities = self.model.predict_proba(X)[0]
            prediction_idx = np.argmax(probabilities)
            prediction_label = self.le.classes_[prediction_idx]
            confidence = probabilities[prediction_idx]

            # Only report if it's NOT 'Safe' and confidence is high enough
            if prediction_label != 'Safe' and confidence > 0.5:
                detections.append({
                    'type': prediction_label,
                    'start_line': start_line,
                    'end_line': end_line,
                    'confidence': float(confidence),
                    'snippet_preview': snippet.strip().split('\n')[0][:50] + "..."
                })

        # Remove duplicate detections for the same lines
        # (Since windows may overlap, we pick the one with highest confidence)
        unique_detections = []
        if detections:
            # Simple deduplication: if multiple windows detect same type, group them
            detections.sort(key=lambda x: x['confidence'], reverse=True)
            seen_lines = set()
            for d in detections:
                line_range = range(d['start_line'], d['end_line'] + 1)
                if not any(l in seen_lines for l in line_range):
                    unique_detections.append(d)
                    seen_lines.update(line_range)

        return unique_detections

if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            code = f.read()
    else:
        code = """
    public class TestApp {
        public void process(String data) {
            // Some safe code here
            int x = 10;
            System.out.println("Processing...");
            
            // A SQL Injection hotspot
            String query = "SELECT * FROM users WHERE name = '" + data + "'";
            db.execute(query);
            
            // More safe code
            log.info("Finished database op");
            
            // A Command Injection hotspot
            Runtime.getRuntime().exec("ping " + data);
        }
    }
    """
    
    analyzer = AIAnalyzer()
    results = analyzer.analyze(code)
    
    print(f"AI Analysis Results ({len(results)} vulnerabilities found):")
    for r in results:
        print(f"[{r['type']}] Confidence: {r['confidence']:.2%} | Lines: {r['start_line']}-{r['end_line']}")