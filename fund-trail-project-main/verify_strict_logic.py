import pandas as pd
import io

def test_extraction_logic():
    # Simulate Excel data with varying column names and case
    # User requirement: 
    # - Match 'Transaction Id / UTR Number2' (and case variants)
    # - IGNORE 'Transaction Id / UTR Number'
    
    # Case 1: Ideal case
    data1 = {
        'Account No./ (Wallet /PG/PA) Id': ['123'],
        'Transaction ID / UTR Number2': ['CORRECT_ID_1'],
        'Transaction ID / UTR Number': ['WRONG_ID_1']
    }
    
    # Case 2: Case variation in header
    data2 = {
        'Account No./ (Wallet /PG/PA) Id': ['456'],
        'Transaction Id / UTR Number2': ['CORRECT_ID_2'],
        'Transaction Id / UTR Number': ['WRONG_ID_2']
    }
    
    # Case 3: Only wrong column exists (Should be empty, NOT wrong id)
    data3 = {
        'Account No./ (Wallet /PG/PA) Id': ['789'],
        'Transaction ID / UTR Number': ['WRONG_ID_3']
    }
    
    # Case 4: Extra spaces in header (handled by normalize_columns logic simulation)
    data4 = {
        'Account No./ (Wallet /PG/PA) Id': ['101'],
        'Transaction ID / UTR Number2 ': ['CORRECT_ID_4'] 
    }

    def normalize_columns(df):
        return [str(c).encode('ascii', 'ignore').decode().strip().replace('\u00A0', ' ').replace('\xa0', ' ') for c in df.columns]

    print("Testing extraction logic...")
    
    for i, data in enumerate([data1, data2, data3, data4]):
        df = pd.DataFrame(data)
        df.columns = normalize_columns(df)
        
        row = df.iloc[0]
        
        # Logic from app.py
        txn_id_val = ''
        for col_name in ['Transaction Id / UTR Number2', 'Transaction ID / UTR Number2']:
            val = str(row.get(col_name, '')).strip()
            if val and val.lower() != 'nan':
                txn_id_val = val
                break
                
        print(f"Test Case {i+1}: Got '{txn_id_val}'")

if __name__ == "__main__":
    test_extraction_logic()
