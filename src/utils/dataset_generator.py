import random
import json
import os

class DatasetGenerator:
    """Generate synthetic code samples with security labels"""
    
    def __init__(self):
        self.safe_patterns = [
            'name = "John";',
            'age = 25;',
            'result = calculate(x, y);',
            'print("Hello World");',
            'for i in range(10):',
            'if x > 0:',
            'return true;'
        ]
        
        self.vulnerable_patterns = {
            'sql_injection': [
                'query = "SELECT * FROM users WHERE id=\'" + input + "\'";',
                'sql = "INSERT INTO logs VALUES (\'" + user_data + "\')";',
                'cmd = "DELETE FROM products WHERE id=" + product_id;',
                'result = mysql_query("SELECT * FROM " + table_name + " WHERE id=" + id);'
            ],
            'command_injection': [
                'os.system("ls " + user_input);',
                'subprocess.call("cat " + filename, shell=True);',
                'eval(user_code);',
                'exec("print(" + data + ")");'
            ],
            'xss': [
                'document.write("<div>" + user_content + "</div>");',
                'element.innerHTML = user_data;',
                'location.href = "javascript:" + user_script;',
                'window.open("data:text/html," + untrusted_html);'
            ]
        }
    
    def generate_sample(self, label='safe'):
        """Generate a single code sample"""
        if label == 'safe':
            code = random.choice(self.safe_patterns)
            return {
                'code': code,
                'label': 0,  # 0 = safe
                'vulnerability_type': 'none'
            }
        else:
            vuln_type = random.choice(list(self.vulnerable_patterns.keys()))
            code = random.choice(self.vulnerable_patterns[vuln_type])
            return {
                'code': code,
                'label': 2,  # 2 = malicious
                'vulnerability_type': vuln_type
            }
    
    def generate_dataset(self, n_samples=100):
        """Generate a balanced dataset"""
        dataset = []
        
        # Generate safe samples (50%)
        for _ in range(n_samples // 2):
            dataset.append(self.generate_sample('safe'))
        
        # Generate vulnerable samples (50%)
        for _ in range(n_samples // 2):
            # Randomly choose vulnerability type
            vuln_type = random.choice(['sql_injection', 'command_injection', 'xss'])
            sample = self.generate_sample(vuln_type)
            dataset.append(sample)
        
        # Shuffle
        random.shuffle(dataset)
        return dataset
    
    def save_dataset(self, dataset, filename='data/raw/dataset.json'):
        """Save dataset to JSON file"""
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w') as f:
            json.dump(dataset, f, indent=2)
        print(f"Dataset saved to {filename} with {len(dataset)} samples")

# Generate and save dataset
if __name__ == "__main__":
    generator = DatasetGenerator()
    dataset = generator.generate_dataset(n_samples=200)
    generator.save_dataset(dataset)