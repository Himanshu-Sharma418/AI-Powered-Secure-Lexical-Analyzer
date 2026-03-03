import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from ml.feature_extractor import FeatureExtractor

class StaticAnalyzer:
    """Performs security analysis of code based on some static rules"""
    
    def __init__(self):
        self.extractor = FeatureExtractor()
        
    def static_analyze(self, code):
        """Tells if a code is insecure or not based on its features"""
        features = self.extractor.extract_features(code)
        
        vulne = {
            'Safe': 1,
            'SQL Injection': 0,
            'Command Injection': 0,
            'XSS': 0
        }
        
        if features['sql_and_concat_same_line'] == 1:
            vulne['SQL Injection'] = 1
            vulne['Safe'] = 0
        if features['has_command_keyword'] == 1 and features['has_direct_exec'] == 1:
            vulne['Command Injection'] = 1
            vulne['Safe'] = 0
        if features['has_xss_keyword'] == 1 and features['has_inline_script'] == 1:
            vulne['XSS'] = 1
            vulne['Safe'] = 0
            
        return vulne
    
if __name__ == "__main__":
    analyzer = StaticAnalyzer()
    
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r") as f:
            code = f.read()
    else:
        code = 'query = "SELECT * FROM users WHERE id=\'" + input + "\'";'
        
    vulne = analyzer.static_analyze(code)
    if vulne['Safe'] == 1:
        print("There were no vulnerabilities detected")
    else:
        for key, value in vulne.items():
            if key == 'Safe': continue
            if value == 1:
                print(f"This code may be suceptible to {key}")