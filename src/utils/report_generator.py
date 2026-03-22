import json
from collections import defaultdict

class ReportGenerator:
    """Generates security reports with remediation advice"""
    
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
        """Prints a remediation report to the console"""
        if not results:
            print("No vulnerabilities detected.")
            return

        print("=" * 80)
        print("SECURITY ANALYSIS REPORT")
        print("=" * 80)

        # Group results by vulnerability type
        grouped_results = defaultdict(list)
        for r in results:
            grouped_results[r['type']].append(r)

        for vuln_type, occurrences in grouped_results.items():
            print(f"\n>>> VULNERABILITY TYPE: {vuln_type} ({len(occurrences)} occurrences)")
            print("-" * 80)
            
            # List all occurrences first
            for i, occ in enumerate(occurrences, 1):
                status_str = f"[{occ['status']}]"
                print(f"   {i}. Line {occ['line']:<4} | {status_str:<25} | Confidence: {occ['confidence']:.2%}")
                print(f"      Code: {occ['snippet']}")
            
            # Provide remediation advice ONLY ONCE for this type
            solution = self.solutions.get(vuln_type)
            if solution:
                print(f"\n   --- REMEDIATION FOR {vuln_type.upper()} ---")
                print(f"   Title:       {solution['title']}")
                print(f"   Description: {solution['description']}")
                print(f"   Recommended: {solution['fix']}")
                print("\n   Code Example:")
                for line in solution['example']:
                    print(f"      {line}")
            
            print("-" * 80)

    def generate_json_report(self, results, output_file):
        """Exports the analysis and remediation data to a JSON file"""
        report_data = {
            'summary': {
                'total_vulnerabilities': len(results),
                'high_confidence': sum(1 for r in results if r['status'] == 'Vulnerable')
            },
            'findings': results,
            'remediation_database': self.solutions
        }

        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=4)
        print(f"JSON report saved to: {output_file}")

if __name__ == "__main__":
    # Example usage for testing
    dummy_results = [
        {
            'type': 'SQL Injection',
            'line': 10,
            'status': 'Vulnerable',
            'confidence': 0.95,
            'snippet': 'query = "SELECT * FROM users WHERE id=" + id;'
        }
    ]
    
    gen = ReportGenerator()
    gen.generate_console_report(dummy_results)
