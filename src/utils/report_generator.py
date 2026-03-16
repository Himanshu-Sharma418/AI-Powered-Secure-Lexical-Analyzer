import json

class ReportGenerator:
    """Generates security reports with remediation advice for detected vulnerabilities"""
    
    def __init__(self):
        # Professional remediation database
        self.solutions = {
            'SQL Injection': {
                'title': 'Use Parameterized Queries (PreparedStatements)',
                'description': 'Never concatenate user input directly into SQL strings. This allows attackers to "break out" of the query and execute arbitrary SQL commands.',
                'fix': 'Use the PreparedStatement API to safely bind variables.',
                'example': [
                    '// VULNERABLE',
                    'String query = "SELECT * FROM users WHERE id = \'" + input + "\'";',
                    '',
                    '// SECURE (Fix)',
                    'String query = "SELECT * FROM users WHERE id = ?";',
                    'PreparedStatement pstmt = connection.prepareStatement(query);',
                    'pstmt.setString(1, input);',
                    'ResultSet rs = pstmt.executeQuery();'
                ]
            },
            'Cross-Site Scripting (XSS)': {
                'title': 'Implement Output Encoding',
                'description': 'User-provided data must be encoded before being rendered in the browser to prevent it from being interpreted as active content (like <script> tags).',
                'fix': 'Use a trusted library like OWASP Java Encoder for context-aware encoding.',
                'example': [
                    '// VULNERABLE',
                    'writer.println("<div>" + userInput + "</div>");',
                    '',
                    '// SECURE (Fix)',
                    'import org.owasp.encoder.Encode;',
                    'writer.println("<div>" + Encode.forHtml(userInput) + "</div>");'
                ]
            },
            'Command Injection': {
                'title': 'Use Parameterized Process Execution',
                'description': 'Executing shell commands with concatenated strings allows attackers to append their own commands using separators like ; or &&.',
                'fix': 'Use ProcessBuilder and pass arguments as a separate list, which prevents shell interpretation.',
                'example': [
                    '// VULNERABLE',
                    'Runtime.getRuntime().exec("git checkout " + branchName);',
                    '',
                    '// SECURE (Fix)',
                    'ProcessBuilder pb = new ProcessBuilder("git", "checkout", branchName);',
                    'pb.start();'
                ]
            }
        }

    def generate_console_report(self, results):
        """Prints a detailed remediation report to the console"""
        if not results:
            print("No vulnerabilities detected.")
            return

        print("=" * 80)
        print("SECURITY ANALYSIS REPORT")
        print("=" * 80)

        for i, r in enumerate(results, 1):
            vuln_type = r['type']
            solution = self.solutions.get(vuln_type, {})
            
            print(f"{i}. [{r['status']}] {vuln_type} at Line {r['line']}")
            print(f"   Detected Code: {r['snippet']}")
            print(f"   AI Confidence: {r['confidence']:.2%}")
            print("-" * 40)
            
            if solution:
                print(f"   REMEDIATION: {solution['title']}")
                print(f"   Description: {solution['description']}")
                print(f"   Recommended Fix: {solution['fix']}")
                print("\n   Code Example:")
                for line in solution['example']:
                    print(f"      {line}")
            else:
                print("   No specific remediation template available for this type.")
            
            print("-" * 80)

    def generate_json_report(self, results, output_file):
        """Exports the analysis and remediation data to a JSON file"""
        report_data = {
            'summary': {
                'total_vulnerabilities': len(results),
                'high_confidence': sum(1 for r in results if r['status'] == 'Vulnerable')
            },
            'findings': []
        }

        for r in results:
            finding = {
                'type': r['type'],
                'line': r['line'],
                'status': r['status'],
                'confidence': r['confidence'],
                'snippet': r['snippet'],
                'remediation': self.solutions.get(r['type'], {})
            }
            report_data['findings'].append(finding)

        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=4)
        print(f"JSON report saved to: {output_file}")

if __name__ == "__main__":
    # Example usage
    dummy_results = [{
        'type': 'SQL Injection',
        'line': 42,
        'status': 'Vulnerable',
        'confidence': 0.89,
        'snippet': 'query = "SELECT * FROM users WHERE id=" + id;'
    }]
    
    gen = ReportGenerator()
    gen.generate_console_report(dummy_results)
