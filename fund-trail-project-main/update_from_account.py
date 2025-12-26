from app import db, Transaction

# Update from_account for Layer 1 if empty, set to ack_no
transactions = Transaction.query.filter(Transaction.layer == 1, (Transaction.from_account.is_(None)) | (Transaction.from_account == '')).all()

for t in transactions:
    t.from_account = t.ack_no

db.session.commit()
print(f"Updated {len(transactions)} Layer 1 transactions with from_account = ack_no.")
