"""
Simplified web language grammar for testing
Supports: variables, strings, SQL-like queries, basic functions
"""

# Language keywords (web-focused)
KEYWORDS = {
    'False', 'None', 'True', 'and', 'as', 'assert', 'async', 
    'await', 'break', 'class', 'continue', 'def', 'del', 'elif', 
    'else', 'except', 'finally', 'for', 'from', 'global', 'if', 
    'import', 'in', 'is', 'lambda', 'nonlocal', 'not', 'or', 
    'pass', 'raise', 'return', 'try', 'while', 'with', 'yield',
    'SELECT', 'FROM', 'WHERE', 'INSERT', 'INTO', 'VALUES',
    'UPDATE', 'DELETE', 'DROP', 'UNION',
    'echo', 'print', 'system', 'exec', 'eval'
}

# Operators
OPERATORS = {
    '+', '-', '*', '/', '=', '==', '!=', '<', '>', '<=', '>=',
    '&&', '||', '!', '&', '|'
}

# Delimiters
DELIMITERS = {
    ';', ',', '(', ')', '{', '}', '[', ']', '.', '"', "'"
}

# Token types
TOKEN_TYPES = {
    'KEYWORD': 'KEYWORD',
    'IDENTIFIER': 'IDENTIFIER',
    'STRING': 'STRING',
    'NUMBER': 'NUMBER',
    'OPERATOR': 'OPERATOR',
    'DELIMITER': 'DELIMITER',
    'COMMENT': 'COMMENT',
    'WHITESPACE': 'WHITESPACE'
}