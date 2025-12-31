#!/usr/bin/env python
"""
Debug script to check Transaction ID extraction from Excel file
Run this after uploading an Excel file to see what's being extracted
"""

import pandas as pd
import re
from pathlib import Path

def norm(s):
    s = str(s).replace('\u00a0', ' ')
    s = re.sub(r'[\s/_\-\.]+', ' ', s).lower().strip()
    return s

def normalize_columns(cols):
    return [str(c).encode('ascii', 'ignore').decode().strip().replace('\u00A0', ' ').replace('\xa0', ' ') for c in cols]

# Find the most recently uploaded Excel file
uploads_dir = Path('uploads')
if uploads_dir.exists():
    excel_files = list(uploads_dir.glob('*.xlsx')) + list(uploads_dir.glob('*.xls'))
    if excel_files:
        latest_file = max(excel_files, key=lambda p: p.stat().st_mtime)
        print(f"\n{'='*80}")
        print(f"Analyzing: {latest_file.name}")
        print(f"{'='*80}\n")
        
        xls = pd.ExcelFile(latest_file)
        print(f"Available sheets: {xls.sheet_names}\n")
        
        if 'Money Transfer to' in xls.sheet_names:
            df = pd.read_excel(latest_file, sheet_name='Money Transfer to')
            df.columns = normalize_columns(df.columns)
            
            print(f"{'='*80}")
            print(f"Column Names in 'Money Transfer to' sheet:")
            print(f"{'='*80}")
            for i, col in enumerate(df.columns):
                print(f"  {i}: '{col}'")
            
            print(f"\n{'='*80}")
            print(f"Looking for Transaction ID / UTR Number2 column...")
            print(f"{'='*80}\n")
            
            # Check for matches
            for col in df.columns:
                nc = norm(col)
                has_utr = 'utr' in nc
                has_number = 'number' in nc
                has_txn = any(x in nc for x in ['transaction', 'txn', 'id'])
                
                if has_utr or ('number' in nc and 'utr' in nc):
                    print(f"Potential match: '{col}'")
                    print(f"  Normalized: '{nc}'")
                    print(f"  Has 'utr': {has_utr}, Has 'number': {has_number}, Has 'txn/id': {has_txn}")
                    if not df.empty:
                        val = df.iloc[0].get(col, '')
                        print(f"  First row value: {val}")
                    print()
            
            print(f"{'='*80}")
            print(f"First 5 rows of data:")
            print(f"{'='*80}\n")
            print(df.head(5).to_string())
            
        else:
            print("ERROR: 'Money Transfer to' sheet not found!")
    else:
        print("No Excel files found in uploads directory")
else:
    print(f"uploads directory not found at {uploads_dir.absolute()}")
