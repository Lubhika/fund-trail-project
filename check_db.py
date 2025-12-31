import pymysql
from sqlalchemy import create_engine, text

# Database connection
engine = create_engine('mysql+pymysql://root:root%40123@localhost/fundtrail_db')

with engine.connect() as conn:
    # Check all ACK numbers in transactions
    result = conn.execute(text('SELECT DISTINCT ack_no FROM transaction WHERE ack_no IS NOT NULL AND ack_no != ""'))
    ack_nos = [row[0] for row in result]
    print('Available ACK Numbers in transactions:', ack_nos)

    # Check uploaded files and their associated ACK numbers
    result = conn.execute(text('SELECT id, filename FROM uploaded_file ORDER BY upload_time DESC LIMIT 10'))
    files = result.fetchall()
    for file in files:
        file_id, filename = file
        result_ack = conn.execute(text(f'SELECT DISTINCT ack_no FROM transaction WHERE upload_id = {file_id} AND ack_no IS NOT NULL AND ack_no != ""'))
        acks = [row[0] for row in result_ack]
        print(f'File: {filename}, ID: {file_id}, ACKs: {acks}')    
    # Check TXN_ID field status
    print("\n" + "="*80)
    print("TXN_ID Status Check:")
    print("="*80)
    result = conn.execute(text('SELECT COUNT(*) FROM transaction WHERE txn_id IS NOT NULL AND txn_id != ""'))
    count_with_txn = result.fetchone()[0]
    result = conn.execute(text('SELECT COUNT(*) FROM transaction'))
    total_count = result.fetchone()[0]
    print(f"Transactions with TXN_ID: {count_with_txn}/{total_count}")
    
    # Show some examples
    print("\nSample transactions with TXN_ID:")
    result = conn.execute(text('SELECT ack_no, to_account, txn_date, amount, txn_id FROM transaction WHERE txn_id IS NOT NULL AND txn_id != "" LIMIT 5'))
    for row in result:
        print(f"  ACK: {row[0]}, Account: {row[1]}, Date: {row[2]}, Amount: {row[3]}, TXN_ID: {row[4]}")
    
    print("\nSample transactions WITHOUT TXN_ID:")
    result = conn.execute(text('SELECT ack_no, to_account, txn_date, amount FROM transaction WHERE (txn_id IS NULL OR txn_id = "") LIMIT 5'))
    for row in result:
        print(f"  ACK: {row[0]}, Account: {row[1]}, Date: {row[2]}, Amount: {row[3]}")