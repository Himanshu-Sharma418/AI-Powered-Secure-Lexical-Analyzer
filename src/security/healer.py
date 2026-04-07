import re
import os
import sys

# Add project root to path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

class CodeHealer:
    """Simple code healer for SQLi"""
    
    def __init__(self):
        self.type_mapping = {
            'SQLI': 'SQL Injection',
            'SQL INJECTION': 'SQL Injection',
            'COMMAND INJECTION': 'Command Injection',
            'COMMAND_INJECTION': 'Command Injection'
        }

    def _get_indentation(self, line):
        """Extracts leading whitespace from a line"""
        match = re.match(r'^(\s*)', line)
        return match.group(1) if match else ""

    def _fix_sqli_multi(self, line, indent):
        """Intelligently heals SQLi with any number of parameters"""
        # Match the assignment structure
        match = re.search(r'String\s+([a-zA-Z0-9_]+)\s*=\s*(.*);', line)
        if not match: return None
        var_name, expr = match.groups()

        # Extract string literals and identifiers in order
        # This regex matches either a double-quoted string (handling escapes) or an identifier
        parts = re.findall(r'("(?:\\.|[^"\\])*?"|[a-zA-Z0-9_]+)', expr)
        
        literals = []
        params = []
        
        # Separate literals and variables
        for p in parts:
            if p.startswith('"'):
                literals.append(p[1:-1]) # remove surrounding double quotes
            else:
                # If it's not a keyword or a number, treat as a parameter
                if p.lower() not in ['select', 'from', 'where', 'and', 'or', 'insert', 'into', 'update', 'set', 'delete']:
                    params.append(p)

        if not params: return None

        # Clean up literals (remove the single quotes usually used for concatenation)
        cleaned_literals = []
        for i, lit in enumerate(literals):
            l = lit
            if i < len(params): # Literal followed by a parameter
                l = l.rstrip().rstrip("'").rstrip()
            if i > 0: # Literal preceded by a parameter
                l = l.lstrip().lstrip("'").lstrip()
            cleaned_literals.append(l)
            
        # Reconstruct the query string with '?' placeholders
        # Joining with " ? " and then collapsing multiple spaces ensures clean formatting
        query_content = " ? ".join(cleaned_literals)
        query_content = re.sub(r'\s+', ' ', query_content).strip()
        
        # Build multi-line fix
        fix_lines = [
            f'String {var_name} = "{query_content}";',
            f'PreparedStatement pstmt = connection.prepareStatement({var_name});'
        ]
        for i, p in enumerate(params, 1):
            fix_lines.append(f'pstmt.setString({i}, {p});')
        
        return "\n".join([indent + l for l in fix_lines])

    def _fix_command_injection(self, line, indent):
        """Heals command injection using ProcessBuilder"""
        # Flexible regex for Runtime.exec and concatenation
        match = re.search(r'Runtime.*?\.exec\s*\(\s*"(.*?)"\s*\+\s*(.*?)\s*\)', line, re.IGNORECASE)
        if not match:
            # Also try assignment pattern: String cmd = "..." + var;
            match = re.search(r'String\s+([a-zA-Z0-9_]+)\s*=\s*"(.*?)"\s*\+\s*(.*);', line, re.IGNORECASE)
            if not match: return None
            
            var_name, cmd_base, input_var = match.groups()
            cmd = cmd_base.strip().split()[0].replace('"', '')
            fix_lines = [
                f'ProcessBuilder pb = new ProcessBuilder("{cmd}", {input_var.strip()});',
                f'// Process p = pb.start();'
            ]
        else:
            cmd_base, input_var = match.groups()
            cmd = cmd_base.strip().split()[0].replace('"', '')
            fix_lines = [
                f'ProcessBuilder pb = new ProcessBuilder("{cmd}", {input_var.strip()});',
                f'Process p = pb.start();'
            ]
            
        return "\n".join([indent + l for l in fix_lines])

    def suggest_fix(self, vuln_type, line_content):
        """Determines which healing strategy to apply"""
        norm_type = self.type_mapping.get(vuln_type.upper(), vuln_type)
        indent = self._get_indentation(line_content)
        
        if norm_type == 'SQL Injection':
            return self._fix_sqli_multi(line_content, indent)
        elif norm_type == 'Command Injection':
            return self._fix_command_injection(line_content, indent)
            
        return None
