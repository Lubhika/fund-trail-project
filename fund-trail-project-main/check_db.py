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
