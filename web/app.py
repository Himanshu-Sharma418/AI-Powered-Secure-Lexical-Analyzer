import os
import sys
from flask import Flask, request, jsonify, render_template

# Ensure project root is in the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.security.hybrid_analyzer import HybridAnalyzer
from src.utils.report_generator import ReportGenerator

app = Flask(__name__)

# Initialize the analyzer once at startup
analyzer = HybridAnalyzer()
generator = ReportGenerator()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_code():
    data = request.json
    code = data.get('code', '')
    
    if not code:
        return jsonify({'error': 'No code provided'}), 400
        
    # 1. Run the Hybrid Analysis
    results = analyzer.analyze(code)
    
    # 2. Enrich results with remediation advice from the generator
    enriched_results = []
    for r in results:
        vuln_type = r['type']
        remediation = generator.solutions.get(vuln_type, {})
        
        enriched_results.append({
            'type': vuln_type,
            'line': r['line'],
            'status': r['status'],
            'confidence': r['confidence'],
            'snippet': r['snippet'],
            'remediation': remediation
        })
        
    return jsonify({
        'summary': {
            'total': len(enriched_results),
            'vulnerable': sum(1 for r in enriched_results if r['status'] == 'Vulnerable'),
            'potential': sum(1 for r in enriched_results if r['status'] == 'Potentially Vulnerable')
        },
        'results': enriched_results
    })

if __name__ == '__main__':
    # Using 0.0.0.0 to allow access from local network if needed
    app.run(debug=True, port=5000)
