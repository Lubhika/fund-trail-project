from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from flask_login import UserMixin

db = SQLAlchemy()

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    layer = db.Column(db.Integer)
    from_account = db.Column(db.String(100))
    to_account = db.Column(db.String(100))
    ack_no = db.Column(db.String(100))
    bank_name = db.Column(db.String(100))
    ifsc_code = db.Column(db.String(50))
    txn_date = db.Column(db.String(100))
    txn_id = db.Column(db.String(100))
    amount = db.Column(db.Float)
    disputed_amount = db.Column(db.Float)
    action_taken = db.Column(db.String(255))
    account_number = db.Column(db.String(50))  # ✅ Add this line
    state = db.Column(db.String(50))  # Cache state from IFSC

    # New fields for ATM withdrawal
    atm_id = db.Column(db.String(100))
    atm_withdraw_amount = db.Column(db.Float)
    atm_withdraw_date = db.Column(db.String(100))
    atm_location = db.Column(db.String(200))

    # New fields for Cheque withdrawal
    cheque_no = db.Column(db.String(100))
    cheque_withdraw_amount = db.Column(db.Float)
    cheque_withdraw_date = db.Column(db.String(100))
    cheque_ifsc = db.Column(db.String(50))

    put_on_hold_txn_id = db.Column(db.String(100))
    put_on_hold_date = db.Column(db.String(100))
    put_on_hold_amount = db.Column(db.Float)

# Add to Transaction model in models.py or wherever your SQLAlchemy models are defined
    kyc_name = db.Column(db.String(120))
    kyc_aadhar = db.Column(db.String(20))
    kyc_mobile = db.Column(db.String(20))
    kyc_address = db.Column(db.String(200))
    upload_id = db.Column(db.Integer, db.ForeignKey('uploaded_file.id'))

# from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.Text)
    role = db.Column(db.String(50))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class UploadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    data = db.Column(db.LargeBinary)
    uploader = db.Column(db.String(100))  # session['username']
    mimetype = db.Column(db.String(100))
    # upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    upload_time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    transaction_count = db.Column(db.Integer, default=0)
    # ✅ Add this line
    transaction = db.relationship('Transaction', backref='upload', uselist=False)

# models.py
class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ack_no = db.Column(db.String(50), unique=True, nullable=False)
    file_name = db.Column(db.String(200))
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    upload_time = db.Column(db.DateTime)



