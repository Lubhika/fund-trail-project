import pandas as pd

def fuzzy_find_column(columns, required_substrs, excluded_substrs=None):
    """
    Finds a column name that contains all required substrings (case-insensitive).
    Optionally excludes columns containing any excluded substrings.
    """
    if excluded_substrs is None:
        excluded_substrs = []
        
    for col in columns:
        col_lower = col.lower()
        
        # Check if all required substrings are present
        if all(sub.lower() in col_lower for sub in required_substrs):
            # Check if any excluded substrings are present
            if not any(ex.lower() in col_lower for ex in excluded_substrs):
                return col
    return None

def test_fuzzy_matcher():
    # Test cases based on potential real-world headers
    test_headers_sets = [
        # Case 1: Standard
        ['Account No', 'Transaction ID / UTR Number2', 'Transaction ID / UTR Number'],
        # Case 2: Messy spacing
        ['Account No', 'Transaction   ID / UTR   Number2 ', 'Transaction ID / UTR Number'],
        # Case 3: Case variation
        ['Account No', 'transaction id / utr number2', 'transaction id / utr number'],
        # Case 4: User scenario (ensure we don't pick the wrong one)
        ['Account No', 'Transaction ID / UTR Number'], # Should return None if looking for Number2
        # Case 5: Weird encoding simulation (already normalized)
        ['Account No', 'Transaction ID / UTR Number2'],
    ]

    print("Testing Fuzzy Matcher...")
    
    for i, headers in enumerate(test_headers_sets):
        print(f"\nTest Set {i+1}: {headers}")
        
        # We want to find "Number2" specifically
        target_col = fuzzy_find_column(headers, ['transaction', 'number2'])
        print(f"  Found: '{target_col}'")
        
        if i == 3: # Case where only wrong column exists
            if target_col is None:
                print("  ✅ Correctly ignored the wrong column")
            else:
                print("  ❌ FAILED: Picked wrong column")
        elif target_col:
             print(f"  ✅ Picked a valid column: {target_col}")
        else:
             print("  ❌ FAILED: Could not find column")

if __name__ == "__main__":
    test_fuzzy_matcher()
