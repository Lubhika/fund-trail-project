from app import db, Transaction

# Update account_number to to_account for transactions where account_number is None or empty
transactions = Transaction.query.filter((Transaction.account_number.is_(None)) | (Transaction.account_number == '')).all()

for t in transactions:
    t.account_number = t.to_account

db.session.commit()
print(f"Updated {len(transactions)} transactions.")
