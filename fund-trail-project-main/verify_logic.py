import pandas as pd

def test_logic():
    # Test case 1: Column 'Transaction Id / UTR Number2' exists
    data1 = {
        'Account No./ (Wallet /PG/PA) Id': ['123'],
        'Transaction Id / UTR Number2': ['TXN123'],
        'Transaction ID / UTR Number': ['SHOULD_NOT_PICK_THIS']
    }
    df1 = pd.DataFrame(data1)
    
    # Test case 2: Column 'Transaction ID / UTR Number' exists
    data2 = {
        'Account No./ (Wallet /PG/PA) Id': ['456'],
        'Transaction ID / UTR Number': ['TXN456']
    }
    df2 = pd.DataFrame(data2)

    # Test case 3: Both exist, should pick Number2
    data3 = {
        'Account No./ (Wallet /PG/PA) Id': ['789'],
        'Transaction Id / UTR Number2': ['TXN789'],
        'Transaction ID / UTR Number': ['TXN_OLD']
    }
    df3 = pd.DataFrame(data3)

    print("Testing logic...")

    for i, df in enumerate([df1, df2, df3]):
        row = df.iloc[0]
        txn_id_val = ''
        for col_name in ['Transaction Id / UTR Number2', 'Transaction ID / UTR Number2', 'Transaction Id / UTR Number', 'Transaction ID / UTR Number']:
            val = str(row.get(col_name, '')).strip()
            if val and val.lower() != 'nan':
                txn_id_val = val
                break
        print(f"Test case {i+1}: Got '{txn_id_val}'")

if __name__ == "__main__":
    test_logic()
