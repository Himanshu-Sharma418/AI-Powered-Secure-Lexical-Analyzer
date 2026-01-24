import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.lexer.tokenizer import SimpleTokenizer

def test_basic_tokenization():
    """Test the basic lexer"""
    tokenizer = SimpleTokenizer()
    
    # Test case 1: Simple assignment
    code = 'name = "John";'
    tokens = tokenizer.tokenize(code)
    print(f"\nTest 1 - Simple assignment:")
    for token in tokens:
        print(f"  {token.type}: '{token.value}'")
    
    # Test case 2: SQL-like query
    code = 'query = "SELECT * FROM users WHERE id=" + user_id;'
    tokens = tokenizer.tokenize(code)
    print(f"\nTest 2 - SQL query:")
    for token in tokens:
        print(f"  {token.type}: '{token.value}'")
    
    # Test case 3: Command injection pattern
    code = 'system("ls " + user_input);'
    tokens = tokenizer.tokenize(code)
    print(f"\nTest 3 - Command injection:")
    for token in tokens:
        print(f"  {token.type}: '{token.value}'")
    
    return len(tokens) > 0

if __name__ == "__main__":
    success = test_basic_tokenization()
    if success:
        print("\nBasic lexer test PASSED")
    else:
        print("\nBasic lexer test FAILED")