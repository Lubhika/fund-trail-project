import sys
import os
sys.path.append(os.path.join(os.getcwd(), 'working file repeatcr(15-10)/fundtrail_backend_web_ (2)_updated/fundtrail_backend_web_/fundtrail_backend_web_/fundtrail_backend_web'))

from models import db, Transaction
from flask import Flask

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root%40123@localhost/fundtrail_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

def get_state(ifsc):
    try:
        import requests
        response = requests.get(f'https://ifsc.razorpay.com/{ifsc}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get('STATE', 'Unknown')
        else:
            return 'Unknown'
    except:
        return 'Unknown'

with app.app_context():
    db.create_all()
    print('Database updated')

    # Update state for transactions where state is None
    transactions = Transaction.query.filter(Transaction.state.is_(None)).all()
    print(f'Found {len(transactions)} transactions with missing state')
    for t in transactions:
        if t.ifsc_code:
            state = get_state(t.ifsc_code)
            t.state = state
            print(f'Updated {t.ifsc_code} to state {state}')
    db.session.commit()
    print('States updated')
