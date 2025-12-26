from app import app, db, Transaction

def check_db():
    with app.app_context():
        # Get the latest 10 transactions
        txs = Transaction.query.order_by(Transaction.id.desc()).limit(10).all()
        print(f"Found {len(txs)} transactions.")
        for t in txs:
            print(f"ID: {t.id}, Ack: {t.ack_no}, Account: {t.to_account}, TxnID: '{t.txn_id}'")

if __name__ == "__main__":
    check_db()
