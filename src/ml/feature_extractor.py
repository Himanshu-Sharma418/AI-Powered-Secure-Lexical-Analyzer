import sys
import os
import re

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from lexer.tokenizer import SimpleTokenizer

class FeatureExtractor:
    """Extract features from code for ML model"""
    
    def __init__(self):
        self.tokenizer = SimpleTokenizer()
        
        # Security keywords to look for
        self.security_keywords = {
            'sql': {'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 
                   'WHERE', 'FROM', 'INTO', 'VALUES'},
            'command': {'system', 'exec', 'eval', 'popen', 'subprocess', 
                       'os.', 'shell', 'sh'},
            'xss': {'document.write', 'innerHTML', 'outerHTML', 
                   'document.cookie', 'location.href', 'eval', 
                   'setTimeout', 'setInterval'}
        }
        
    def contains_keyword(self, text, keywords):
        for keyword in keywords:
            if keyword in text or keyword.upper() in text or keyword.lower() in text:
                return True
        return False
    
    def extract_features(self, code):
        """Extract features from code string"""
        tokens = self.tokenizer.tokenize(code)
        
        # Basic features
        features = {
            # Token counts
            'num_tokens': len(tokens),
            'num_strings': sum(1 for t in tokens if t.type == 'STRING'),
            'num_keywords': sum(1 for t in tokens if t.type == 'KEYWORD'),
            
            # Security keyword presence
            'has_sql_keyword': 0,
            'has_command_keyword': 0,
            'has_xss_keyword': 0,
            
            # Patterns
            'has_string_concat': 0,  # String + variable pattern
            'has_direct_exec': 0,    # system(), eval()
            'has_inline_script': 0,  # <script> tags

            'sql_and_concat_same_line': 0,
        }
        
        # Analyze tokens
        token_values = [t.value for t in tokens]
        
        # Check for security keywords
        for token in tokens:
            token_upper = token.value.upper()
    
            # Direct keyword match
            if token_upper in self.security_keywords['sql']:
                features['has_sql_keyword'] = 1
            if token.value in self.security_keywords['command']:
                features['has_command_keyword'] = 1
            if token.value in self.security_keywords['xss']:
                features['has_xss_keyword'] = 1
    
            # Check inside string literals
            if token.type == 'STRING':
                if (self.contains_keyword(token.value, self.security_keywords['sql'])):
                    features['has_sql_keyword'] = 1
                if (self.contains_keyword(token.value, self.security_keywords['command'])):
                    features['has_command_keyword'] = 1
                if (self.contains_keyword(token.value, self.security_keywords['xss'])):
                    features['has_xss_keyword'] = 1
            
        # Check for string concatenation with variables
        code_lower = code.lower()
        if '+' in token_values and any(t.type == 'IDENTIFIER' for t in tokens):
            # Look for pattern: "string" + variable or variable + "string"
            for i, token in enumerate(tokens):
                if token.value == '+' and i > 0 and i < len(tokens) - 1:
                    prev_type = tokens[i-1].type
                    next_type = tokens[i+1].type
                    if (prev_type == 'STRING' and next_type == 'IDENTIFIER') or \
                       (prev_type == 'IDENTIFIER' and next_type == 'STRING'):
                        features['has_string_concat'] = 1
                        break
        
        # Check for direct execution
        exec_patterns = ['system(', 'exec(', 'eval(']
        for pattern in exec_patterns:
            if pattern in code:
                features['has_direct_exec'] = 1
                break
        
        # Check for inline scripts
        if '<script>' in code_lower or 'javascript:' in code_lower:
            features['has_inline_script'] = 1

        # SQL keyword and string concatenation on the same line
        lines = code.split('\n')
        sql_keywords_lower = {kw.lower() for kw in self.security_keywords['sql']}
        # Patterns for string concatenation: "..." + var or var + "..."
        # Supports both double and single quotes, handles escaped quotes inside strings.
        concat_pattern = r'''
            (["'])(?:(?=(\\?))\2.)*?\1   # a quoted string (non-greedy)
            \s*\+\s*                     # plus sign with optional whitespace
            [a-zA-Z_][a-zA-Z0-9_]*       # an identifier
        '''
        concat_pattern2 = r'''
            [a-zA-Z_][a-zA-Z0-9_]*       # an identifier
            \s*\+\s*                     # plus sign with optional whitespace
            (["'])(?:(?=(\\?))\2.)*?\3   # a quoted string
        '''
        # Combine patterns and compile with re.VERBOSE to allow comments and whitespace
        combined_pattern = re.compile(f'{concat_pattern}|{concat_pattern2}', re.VERBOSE)

        for line in lines:
            # Check for SQL keyword in this line (case‑insensitive)
            line_lower = line.lower()
            has_sql = any(kw in line_lower for kw in sql_keywords_lower)
            if not has_sql:
                continue

            # Check for string concatenation pattern in the same line
            if combined_pattern.search(line):
                features['sql_and_concat_same_line'] = 1
                break
        
        return features

# Test feature extraction
if __name__ == "__main__":
    extractor = FeatureExtractor()
    
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r") as f:
            code = f.read()
    else:
        code = 'query = "SELECT * FROM users WHERE id=\'" + input + "\'";'
        
    features = extractor.extract_features(code)
    for key, value in features.items():
        print(f"    {key}: {value}")