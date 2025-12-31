from flask import Flask, render_template, request, redirect, session, url_for, flash, send_file, jsonify
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from collections import defaultdict
import os
import io
from models import db, User, Transaction, UploadedFile, Complaint, UsageLog
import pandas as pd  # pyright: ignore[reportMissingImports]
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import login_required, LoginManager, login_user  # pyright: ignore[reportMissingImports]
from datetime import timezone, timedelta, datetime
from sqlalchemy import func, desc, inspect, text
from flask_migrate import Migrate  # pyright: ignore[reportMissingModuleSource]
import pymysql  # pyright: ignore[reportMissingModuleSource]
pymysql.install_as_MySQLdb()
import requests
import concurrent.futures
import re

app = Flask(__name__)

migrate = Migrate(app, db)

# Cache for IFSC to state mappings to avoid repeated API calls
ifsc_cache = {}

# IFSC district code to state mapping
DISTRICT_TO_STATE = {
    '01': 'Jammu and Kashmir',
    '02': 'Himachal Pradesh',
    '03': 'Punjab',
    '04': 'Chandigarh',
    '05': 'Uttarakhand',
    '06': 'Haryana',
    '07': 'Delhi',
    '08': 'Rajasthan',
    '09': 'Uttar Pradesh',
    '10': 'Bihar',
    '11': 'Sikkim',
    '12': 'Arunachal Pradesh',
    '13': 'Nagaland',
    '14': 'Manipur',
    '15': 'Mizoram',
    '16': 'Tripura',
    '17': 'Meghalaya',
    '18': 'Assam',
    '19': 'West Bengal',
    '20': 'Jharkhand',
    '21': 'Odisha',
    '22': 'Chhattisgarh',
    '23': 'Madhya Pradesh',
    '24': 'Gujarat',
    '25': 'Daman and Diu',
    '26': 'Dadra and Nagar Haveli',
    '27': 'Maharashtra',
    '28': 'Andhra Pradesh',
    '29': 'Karnataka',
    '30': 'Goa',
    '31': 'Lakshadweep',
    '32': 'Kerala',
    '33': 'Tamil Nadu',
    '34': 'Puducherry',
    '35': 'Andaman and Nicobar Islands',
    '36': 'Telangana',
    '37': 'Andhra Pradesh',
    '38': 'Ladakh'
}

def get_state(ifsc):
    if not ifsc or len(ifsc) < 6:
        return 'Unknown'
    if ifsc in ifsc_cache:
        return ifsc_cache[ifsc]
    district_code = ifsc[4:6]
    state = DISTRICT_TO_STATE.get(district_code)
    if state:
        ifsc_cache[ifsc] = state
        return state
    # Fallback to API if not found in mapping
    try:
        response = requests.get(f'https://ifsc.razorpay.com/{ifsc}', timeout=2)
        if response.status_code == 200:
            data = response.json()
            state = data.get('STATE', 'Unknown')
            ifsc_cache[ifsc] = state
            return state
    except Exception as e:
        print(f"Error fetching state for IFSC {ifsc}: {e}")
    ifsc_cache[ifsc] = 'Unknown'
    return 'Unknown'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # redirect to this route if not logged in

# Tell Flask-Login how to load a user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
app.secret_key = 'your-secret-key'

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root%40123@localhost/fundtrail_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)

def ensure_usage_log_table():
    inspector = inspect(db.engine)
    if 'usage_log' not in inspector.get_table_names():
        db.create_all()

def log_usage(action, filename=None, ack_no=None):
    try:
        entry = UsageLog(
            username=session.get('username'),
            role=session.get('role'),
            action=action,
            filename=filename,
            ack_no=ack_no
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        print(f"UsageLog error: {e}")

def ensure_transaction_columns():
    """Add any newly introduced columns to the transaction table if missing."""
    required_columns = {
        'layer': 'INT',
        'from_account': 'VARCHAR(100)',
        'to_account': 'VARCHAR(100)',
        'ack_no': 'VARCHAR(100)',
        'bank_name': 'VARCHAR(100)',
        'ifsc_code': 'VARCHAR(50)',
        'txn_date': 'VARCHAR(100)',
        'txn_id': 'VARCHAR(100)',
        'amount': 'FLOAT',
        'disputed_amount': 'FLOAT',
        'action_taken': 'VARCHAR(255)',
        'account_number': 'VARCHAR(50)',
        'state': 'VARCHAR(50)',
        'atm_id': 'VARCHAR(100)',
        'atm_withdraw_amount': 'FLOAT',
        'atm_withdraw_date': 'VARCHAR(100)',
        'atm_location': 'VARCHAR(200)',
        'cheque_no': 'VARCHAR(100)',
        'cheque_withdraw_amount': 'FLOAT',
        'cheque_withdraw_date': 'VARCHAR(100)',
        'cheque_ifsc': 'VARCHAR(50)',
        'put_on_hold_txn_id': 'VARCHAR(100)',
        'put_on_hold_date': 'VARCHAR(100)',
        'put_on_hold_amount': 'FLOAT',
        'court_order_date': 'VARCHAR(20)',
        'refund_status': 'VARCHAR(50)',
        'refund_amount': 'FLOAT',
        'kyc_name': 'VARCHAR(120)',
        'kyc_aadhar': 'VARCHAR(20)',
        'kyc_mobile': 'VARCHAR(20)',
        'kyc_address': 'VARCHAR(200)',
        'upload_id': 'INT'
    }

    inspector = inspect(db.engine)
    existing_columns = {col['name'] for col in inspector.get_columns('transaction')}
    missing = {col: ddl for col, ddl in required_columns.items() if col not in existing_columns}

    if not missing:
        return

    with db.engine.connect() as conn:
        for col, ddl in missing.items():
            try:
                conn.execute(text(f'ALTER TABLE `transaction` ADD COLUMN `{col}` {ddl}'))
                print(f"Added missing column: {col}")
            except Exception as exc:
                print(f"Skipping column {col}; encountered error: {exc}")

def ensure_user_columns():
    """Add newly introduced columns to the user table if they are missing."""
    required_columns = {
        'name': 'VARCHAR(100)',
        'rank': 'VARCHAR(100)',
        'email': 'VARCHAR(120)',
        'manual_upload_count': 'INT NULL'
    }

    inspector = inspect(db.engine)
    existing_columns = {col['name'] for col in inspector.get_columns('user')}
    missing = {col: ddl for col, ddl in required_columns.items() if col not in existing_columns}

    if not missing:
        return

    with db.engine.connect() as conn:
        for col, ddl in missing.items():
            try:
                conn.execute(text(f'ALTER TABLE `user` ADD COLUMN `{col}` {ddl}'))
                print(f"Added missing user column: {col}")
            except Exception as exc:
                print(f"Skipping user column {col}; encountered error: {exc}")

with app.app_context():
    ensure_transaction_columns()
    ensure_user_columns()
    ensure_usage_log_table()


USERS = {
    'admin': {'password': 'admin123', 'role': 'Admin'},
    'officer': {'password': 'Officer123', 'role': 'Investigative Officer'}
}

VIEW_ONLY_ROLES = {'Viewer'}

@app.route('/')
def home():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # Use .get() to avoid KeyError when viewer fields are disabled
        role = request.form.get('role', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Allow viewer (read-only) login without credentials
        if role == 'Viewer':
            session['username'] = 'viewer'
            session['role'] = 'Viewer'
            log_usage('login')
            return redirect('/index')

        user = User.query.filter_by(username=username, role=role).first()
        if user and user.check_password(password):
            session['username'] = username
            session['role'] = role
            log_usage('login')
            return redirect('/admin_dashboard') if role == 'Admin' else redirect('/index')
        else:
            error = "Invalid credentials or role"
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    log_usage('logout')
    session.clear()
    return redirect('/login')

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'username' in session and session['role'] == 'Admin':
        return render_template('admin_dashboard.html', username=session['username'])
    else:
        return redirect(url_for('login'))


@app.route('/index')
def index():
    if 'username' not in session:
        return redirect('/login')
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if session.get('role') in VIEW_ONLY_ROLES:
        flash("View-only users cannot upload files.", "warning")
        return redirect('/index')
    file = request.files['file']
    if file:
        new_file = UploadedFile(
            filename=file.filename,
            data=file.read()
        )
        db.session.add(new_file)
        db.session.commit()
        return "File uploaded successfully!"
    else:
        return "No file selected", 400

@app.route('/upload_excel', methods=['POST'])
def upload_excel():
    if 'username' not in session:
        return redirect('/login')
    if session.get('role') in VIEW_ONLY_ROLES:
        flash("View-only users cannot upload complaints.", "warning")
        return redirect('/index')

    file = request.files['excel_file']
    if not file or not file.filename.endswith('.xlsx'):
        flash("Invalid file format. Please upload a .xlsx file.", "warning")
        return redirect('/index')

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    file.save(filepath)

    try:
        # ✅ Step 2: Read Excel and extract acknowledgment numbers
        xls = pd.ExcelFile(filepath)
        tx_df = pd.read_excel(xls, sheet_name='Money Transfer to')

        acknos_in_excel = tx_df['Acknowledgement No.'].dropna().unique()

        if len(acknos_in_excel) == 0:
            flash("⚠️ No Acknowledgement numbers found in the Excel file!", "warning")
            return redirect('/index')

        # ✅ Step 3: Check if any of these ACK numbers already exist in DB
        existing_acks = (
            Transaction.query.filter(Transaction.ack_no.in_(acknos_in_excel)).all()
        )
        if existing_acks:
          for record in existing_acks:
             db.session.delete(record)
          db.session.commit()
          flash("ℹ️ Existing ACK numbers found — old records replaced.", "info")

        # ✅ Step 4: Save UploadedFile metadata (after validation)
        uploaded_file = UploadedFile(
            filename=filename,
            data=file.read(),
            uploader=session.get('username'),
            mimetype=file.mimetype
        )
        db.session.add(uploaded_file)
        db.session.commit()
        log_usage('upload_excel', filename=filename)

        # ✅ Step 5: Process and insert transactions
        atm_df = pd.read_excel(xls, sheet_name='Withdrawal through ATM') if 'Withdrawal through ATM' in xls.sheet_names else pd.DataFrame()
        chq_df = pd.read_excel(xls, sheet_name='Cash Withdrawal through Cheque') if 'Cash Withdrawal through Cheque' in xls.sheet_names else pd.DataFrame()
        hold_df = pd.read_excel(xls, sheet_name='Transaction put on hold') if 'Transaction put on hold' in xls.sheet_names else pd.DataFrame()

        def normalize_columns(df):
            return [str(c).encode('ascii', 'ignore').decode().strip().replace('\u00A0', ' ').replace('\xa0', ' ') for c in df.columns]

        # Normalize all dataframe columns for consistent matching
        tx_df.columns = normalize_columns(tx_df)
        if not atm_df.empty: atm_df.columns = normalize_columns(atm_df)
        if not chq_df.empty: chq_df.columns = normalize_columns(chq_df)
        if not hold_df.empty: hold_df.columns = normalize_columns(hold_df)
        
        # DEBUG: Print all columns in Excel
        print("="*80)
        print("[UPLOAD DEBUG] All columns in 'Money Transfer to' sheet:")
        for i, col in enumerate(tx_df.columns):
            print(f"  {i}: '{col}'")
        print("="*80)
        
        # DEBUG: Print first row to see data
        if not tx_df.empty:
            print("[UPLOAD DEBUG] First row data:")
            for col in tx_df.columns:
                val = tx_df.iloc[0].get(col, '')
                if str(val).strip():
                    print(f"  {col}: {val}")
            print("="*80)

        def clean_amount(value):
            if pd.isna(value): return 0.0
            try: return float(str(value).replace(',', '').strip())
            except: return 0.0

        def clean_location(value):
            """Normalize ATM location strings and strip common prefixes."""
            if pd.isna(value) or value is None:
                return None
            s = str(value).strip()
            prefixes = [
                "Place of ATM :-",
                "Place of ATM :",
                "Place/Location of ATM :",
                "Place/Location of ATM",
                "Place / Location of ATM",
                "Place of ATM",
                "Place/Location",
            ]
            for p in prefixes:
                if s.lower().startswith(p.lower()):
                    s = s[len(p):].strip(" :-")
                    break
            return s or None

        def clean_bank_name(value):
            """Clean bank name by removing HTML tags and truncating to 100 characters."""
            if pd.isna(value) or value is None:
                return ''
            # Convert to string and strip whitespace
            s = str(value).strip()
            # Remove HTML tags (e.g., <hr/>, <br/>, etc.)
            s = re.sub(r'<[^>]+>', '', s)
            # Replace multiple spaces with single space
            s = re.sub(r'\s+', ' ', s)
            # Strip again after HTML removal
            s = s.strip()
            # Truncate to 100 characters (column size limit)
            if len(s) > 100:
                s = s[:100]
            return s
        
        def safe_txn_id(val):
            if pd.isna(val) or val is None:
                return ''
            s = str(val).strip()
            if re.fullmatch(r'\d+\.0', s):
                s = s[:-2]
            if re.fullmatch(r'\d+(\.\d+)?e\+\d+', s, flags=re.IGNORECASE):
                try:
                    num = pd.to_numeric(val, errors='coerce')
                    if pd.notna(num):
                        s = f"{int(num):d}"
                except Exception:
                    pass
            return s

        def get_first_value(df, columns):
            """Return first non-empty value for given column names from df."""
            if df.empty:
                return None
            for col in columns:
                if col in df.columns:
                    val = df.iloc[0].get(col)
                    if pd.notna(val) and str(val).strip():
                        return str(val).strip()
            return None
        
        def norm(s):
            s = str(s).replace('\u00a0', ' ')
            s = re.sub(r'[\s/_\-\.]+', ' ', s).lower().strip()
            return s
        
        def get_txn_id_from_row(row, utr2_col=None):
            """Extract Transaction ID / UTR Number2 from a row."""
            # Try the detected column first (if provided)
            if utr2_col and utr2_col in row.index:
                val = row.get(utr2_col, '')
                s = safe_txn_id(val)
                if s:
                    return s
            
            # Try common column name variants (exact matches) - EXPANDED LIST
            variants = [
                'Transaction ID / UTR Number2',
                'Transaction Id / UTR Number2',
                'Transaction ID/ UTR Number2',
                'Transaction ID/UTR Number2',
                'Transaction ID / UTR Number 2',
                'Transaction Id / UTR Number 2',
                'Txn ID / UTR Number2',
                'Txn Id / UTR Number2',
                'UTR Number2',
                'Txn ID / UTR Number 2',
                'Txn Id / UTR Number 2',
                'Transaction ID/UTR Number 2',
                'Txn ID/UTR Number2',
                'Transaction ID / UTR',
                'Transaction ID/UTR',
                'Txn ID/UTR',
                'Transaction ID / UTR Number',
                'Txn ID / UTR Number',
                'UTR Number',
                'UTR',
            ]
            for col in variants:
                if col in row.index:
                    val = row.get(col, '')
                    s = safe_txn_id(val)
                    if s:
                        return s
            
            # Fuzzy matching: Look for columns containing UTR and Number 2 in normalized form
            def norm(s):
                s = str(s).replace('\u00a0', ' ')
                s = re.sub(r'[\s/_\-\.]+', ' ', s).lower().strip()
                return s
            
            for col in row.index:
                nc = norm(col)
                # Match columns that have UTR and (NUMBER 2 or ends with 2) and (TRANSACTION or TXN or ID)
                has_utr = 'utr' in nc
                has_number2 = ('number 2' in nc) or ('number2' in nc) or nc.endswith(' 2')
                has_txn_id = any(x in nc for x in ['transaction', 'txn', 'id'])
                
                if has_utr and has_number2 and has_txn_id:
                    val = row.get(col, '')
                    s = safe_txn_id(val)
                    if s:
                        return s
            
            # Last resort: Try any column with just "UTR" and "NUMBER"
            for col in row.index:
                nc = norm(col)
                if 'utr' in nc and 'number' in nc:
                    val = row.get(col, '')
                    s = safe_txn_id(val)
                    if s:
                        return s
            
            return ''
        
        def find_utr2_column(columns):
            """Find the 'Transaction ID / UTR Number2' column among various possible names."""
            # First, try exact matches
            exact_matches = [
                'Transaction ID / UTR Number2',
                'Transaction Id / UTR Number2',
                'Transaction ID/ UTR Number2',
                'Transaction ID/UTR Number2',
                'Transaction ID / UTR Number 2',
                'Transaction Id / UTR Number 2',
                'Txn ID / UTR Number2',
                'Txn Id / UTR Number2',
                'Txn ID / UTR Number 2',
                'Txn Id / UTR Number 2',
                'UTR Number2',
                'Txn ID/UTR Number2',
                'Transaction ID/UTR Number 2',
                'Transaction ID / UTR',
                'Transaction ID/UTR',
                'Txn ID/UTR',
                'Transaction ID / UTR Number',
            ]
            for col in columns:
                if col in exact_matches:
                    print(f"[FIND_UTR2] Exact match found: {col}")
                    return col
            
            # Then try fuzzy matching with normalized names
            def norm(s):
                s = str(s).replace('\u00a0', ' ')
                s = re.sub(r'[\s/_\-\.]+', ' ', s).lower().strip()
                return s
            
            known_normalized = [
                'transaction id utr number2',
                'transaction id utr number 2',
                'transaction id  utr number2',
                'transaction id  utr number 2',
                'transaction id number2',
                'transaction id utr',
                'txn id utr number2',
                'txn id utr number 2',
                'txn id utr',
                'utr number2',
                'utr number 2',
            ]
            
            normalized_map = {col: norm(col) for col in columns}
            for col, nc in normalized_map.items():
                if nc in known_normalized:
                    print(f"[FIND_UTR2] Normalized match found: '{col}' -> '{nc}'")
                    return col
            
            # Final fallback: Look for columns with all required components
            for col, nc in normalized_map.items():
                has_utr = 'utr' in nc
                has_number2 = ('number 2' in nc) or ('number2' in nc) or nc.endswith(' 2')
                has_txn_id = any(x in nc for x in ['transaction', 'txn', 'id'])
                
                if has_utr and has_number2 and has_txn_id:
                    print(f"[FIND_UTR2] Fuzzy pattern match found: '{col}' -> '{nc}'")
                    return col
            
            # Try ANY column with UTR in name
            for col, nc in normalized_map.items():
                if 'utr' in nc and 'number' in nc:
                    print(f"[FIND_UTR2] Fallback match (UTR + Number): '{col}' -> '{nc}'")
                    return col
            
            print(f"[FIND_UTR2] No match found. Available normalized columns: {list(normalized_map.values())}")
            return None

        utr2_col = find_utr2_column(tx_df.columns)
        print(f"[UPLOAD] Excel columns in 'Money Transfer to': {list(tx_df.columns)}")
        print(f"[UPLOAD] Detected UTR2 column: {utr2_col}")
        
        txn_id_counts = {'found': 0, 'missing': 0}
        for idx, (_, row) in enumerate(tx_df.iterrows()):
            ack_no = str(row.get('Acknowledgement No.', '')).strip()
            if not ack_no:
                # ✅ Skip rows with missing ACK
                continue

            acc_to = str(row.get('Account No', '')).strip()
            atm_info = atm_df[atm_df['Account No./ (Wallet /PG/PA) Id'].astype(str).str.strip() == acc_to] if not atm_df.empty else pd.DataFrame()
            chq_info = chq_df[chq_df['Account No./ (Wallet /PG/PA) Id'].astype(str).str.strip() == acc_to] if not chq_df.empty else pd.DataFrame()
            hold_info = hold_df[hold_df['Account No./ (Wallet /PG/PA) Id'].astype(str).str.strip() == acc_to] if not hold_df.empty else pd.DataFrame()

            extracted_txn_id = get_txn_id_from_row(row, utr2_col)
            if extracted_txn_id:
                txn_id_counts['found'] += 1
                if idx < 2:  # Log first 2 rows with txn_id
                    print(f"[UPLOAD] Row {idx}: ACK={ack_no}, Account={acc_to}, TXN_ID={extracted_txn_id}")
            else:
                txn_id_counts['missing'] += 1
                if idx < 2:  # Log first 2 rows without txn_id
                    print(f"[UPLOAD] Row {idx}: ACK={ack_no}, Account={acc_to}, TXN_ID=EMPTY")
                    # Debug: print what's in the row related to UTR/Transaction
                    for col in row.index:
                        if 'utr' in col.lower() or 'transaction' in col.lower() or 'txn' in col.lower():
                            print(f"  -> {col}: {row.get(col, '')}")
            
            transaction = Transaction(
                layer=int(row.get('Layer', 0)),
                from_account=str(row.get('Account No./ (Wallet /PG/PA) Id', '')).strip(),
                to_account=acc_to,
                account_number=acc_to,
                ack_no=ack_no,
                bank_name=clean_bank_name(row.get('Bank/FIs')),
                ifsc_code=str(row.get('Ifsc Code', '')).strip(),
                txn_date=str(row.get('Transaction Date', '')).strip(),
                txn_id=extracted_txn_id,
                amount=clean_amount(row.get('Transaction Amount')),
                disputed_amount=clean_amount(row.get('Disputed Amount')),
                action_taken=str(row.get('Action Taken By bank', '')).strip(),
                atm_id=str(atm_info.iloc[0]['ATM ID']) if not atm_info.empty else None,
                atm_withdraw_amount=clean_amount(atm_info.iloc[0]['Withdrawal Amount']) if not atm_info.empty else None,
                atm_withdraw_date=str(atm_info.iloc[0]['Withdrawal Date & Time']) if not atm_info.empty else None,
                atm_location=clean_location(get_first_value(atm_info, [
                    'ATM Location',
                    'Location',
                    'ATM Location / City',
                    'ATM Address',
                    'ATM Location/City',
                    'Place/Location of ATM',
                    'Place / Location of ATM'
                ])),
                cheque_no=str(chq_info.iloc[0]['Cheque No']) if not chq_info.empty else None,
                cheque_withdraw_amount=clean_amount(chq_info.iloc[0]['Withdrawal Amount']) if not chq_info.empty else None,
                cheque_withdraw_date=str(chq_info.iloc[0]['Withdrawal Date & Time']) if not chq_info.empty else None,
                cheque_ifsc=str(chq_info.iloc[0]['Ifsc Code']) if not chq_info.empty else None,
                put_on_hold_txn_id=str(hold_info.iloc[0]['Transaction Id / UTR Number']) if not hold_info.empty else None,
                put_on_hold_date=str(hold_info.iloc[0]['Put on hold Date']) if not hold_info.empty else None,
                put_on_hold_amount=clean_amount(hold_info.iloc[0]['Put on hold Amount']) if not hold_info.empty else None,
                upload_id=uploaded_file.id
            )
            db.session.add(transaction)

        db.session.commit()
        print(f"[UPLOAD] Txn ID extraction summary: Found={txn_id_counts['found']}, Missing={txn_id_counts['missing']}")
        flash("✅ Excel uploaded and data saved successfully.", "success")

    except Exception as e:
        db.session.rollback()
        flash(f"Failed to process Excel: {e}", "danger")

    return redirect('/index')

@app.route('/view_graph')
def view_graph():
    ack_no = request.args.get('ack_no')
    try:
        fname_row = db.session.query(UploadedFile.filename).join(Transaction, Transaction.upload_id == UploadedFile.id).filter(Transaction.ack_no == ack_no).order_by(UploadedFile.upload_time.desc()).first()
        fname = fname_row[0] if fname_row else None
        log_usage('view_graph', filename=fname, ack_no=ack_no)
    except Exception as e:
        print(f"UsageLog view_graph error: {e}")
    return redirect(url_for('graph_tree1', ack_no=ack_no))

@app.route('/graph/<ack_no>')
def graph_tree1(ack_no):
    try:
        fname_row = db.session.query(UploadedFile.filename).join(Transaction, Transaction.upload_id == UploadedFile.id).filter(Transaction.ack_no == ack_no).order_by(UploadedFile.upload_time.desc()).first()
        fname = fname_row[0] if fname_row else None
        log_usage('graph_page', filename=fname, ack_no=ack_no)
    except Exception as e:
        print(f"UsageLog graph_page error: {e}")
    return render_template('graph_tree1.html', ack_no=ack_no, role=session.get('role'))

@app.route('/complaints')
def complaints():
    if 'username' not in session:
        return redirect('/login')

    dummy_complaints = [
        {'ack_no': 'ACK123', 'victim_name': 'John Doe', 'date': '2024-12-10', 'status': 'Under Review'},
        {'ack_no': 'ACK456', 'victim_name': 'Jane Smith', 'date': '2024-12-11', 'status': 'Resolved'},
    ]
    return render_template('complaint.html', complaints=dummy_complaints)

@app.route('/graph_data/<ack_no>')
def graph_data(ack_no):
    try:
        ack_no = ack_no.strip()
        print(f"Fetching graph data for ACK: {ack_no}")
        transactions = Transaction.query.filter_by(ack_no=ack_no).all()
        print(f"Found {len(transactions)} transactions for ACK {ack_no}")

        if not transactions:
            print(f"No transactions found for ACK {ack_no}")
            return jsonify({'error': 'No transactions found for this Acknowledgement No.'})

        def norm(s):
            s = str(s).replace('\u00a0', ' ')
            s = re.sub(r'[\s/_\-\.]+', ' ', s).lower().strip()
            return s
        
        def safe_txn_id(val):
            if pd.isna(val) or val is None:
                return ''
            s = str(val).strip()
            if re.fullmatch(r'\d+\.0', s):
                s = s[:-2]
            if re.fullmatch(r'\d+(\.\d+)?e\+\d+', s, flags=re.IGNORECASE):
                try:
                    num = pd.to_numeric(val, errors='coerce')
                    if pd.notna(num):
                        s = f"{int(num):d}"
                except Exception:
                    pass
            return s
        
        def find_utr2_column(columns):
            """Find the 'Transaction ID / UTR Number2' column among various possible names."""
            # First, try exact matches
            exact_matches = [
                'Transaction ID / UTR Number2',
                'Transaction Id / UTR Number2',
                'Transaction ID/ UTR Number2',
                'Transaction ID/UTR Number2',
                'Transaction ID / UTR Number 2',
                'Transaction Id / UTR Number 2',
                'Txn ID / UTR Number2',
                'Txn Id / UTR Number2',
                'Txn ID / UTR Number 2',
                'Txn Id / UTR Number 2',
                'UTR Number2',
                'Txn ID/UTR Number2',
                'Transaction ID/UTR Number 2',
                'Transaction ID / UTR',
                'Transaction ID/UTR',
                'Txn ID/UTR',
                'Transaction ID / UTR Number',
            ]
            for col in columns:
                if col in exact_matches:
                    return col
            
            # Then try fuzzy matching with normalized names
            known_normalized = [
                'transaction id utr number2',
                'transaction id utr number 2',
                'transaction id  utr number2',
                'transaction id  utr number 2',
                'transaction id number2',
                'transaction id utr',
                'txn id utr number2',
                'txn id utr number 2',
                'txn id utr',
                'utr number2',
                'utr number 2',
            ]
            
            normalized_map = {col: norm(col) for col in columns}
            for col, nc in normalized_map.items():
                if nc in known_normalized:
                    return col
            
            # Final fallback: Look for columns with all required components
            for col, nc in normalized_map.items():
                has_utr = 'utr' in nc
                has_number2 = ('number 2' in nc) or ('number2' in nc) or nc.endswith(' 2')
                has_txn_id = any(x in nc for x in ['transaction', 'txn', 'id'])
                
                if has_utr and has_number2 and has_txn_id:
                    return col
            
            # Try ANY column with UTR in name
            for col, nc in normalized_map.items():
                if 'utr' in nc and 'number' in nc:
                    return col
            
            return None
        
        def get_txn_id_from_df_row(row, utr2_col):
            """Extract Transaction ID / UTR Number2 from a dataframe row."""
            # Try the detected column first (if provided)
            if utr2_col and utr2_col in row.index:
                s = safe_txn_id(row.get(utr2_col, ''))
                if s:
                    return s
            
            # Try common column name variants (exact matches) - EXPANDED
            variants = [
                'Transaction ID / UTR Number2',
                'Transaction Id / UTR Number2',
                'Transaction ID/ UTR Number2',
                'Transaction ID/UTR Number2',
                'Transaction ID / UTR Number 2',
                'Transaction Id / UTR Number 2',
                'Txn ID / UTR Number2',
                'Txn Id / UTR Number2',
                'Txn ID / UTR Number 2',
                'Txn Id / UTR Number 2',
                'UTR Number2',
                'Transaction ID/UTR Number 2',
                'Txn ID/UTR Number2',
                'Transaction ID / UTR',
                'Transaction ID/UTR',
                'Txn ID/UTR',
                'Transaction ID / UTR Number',
                'Txn ID / UTR Number',
                'UTR Number',
                'UTR',
            ]
            for col in variants:
                if col in row.index:
                    s = safe_txn_id(row.get(col, ''))
                    if s:
                        return s
            
            # Fuzzy matching: Look for columns containing UTR and Number 2
            for col in row.index:
                nc = norm(col)
                has_utr = 'utr' in nc
                has_number2 = ('number 2' in nc) or ('number2' in nc) or nc.endswith(' 2')
                has_txn_id = any(x in nc for x in ['transaction', 'txn', 'id'])
                
                if has_utr and has_number2 and has_txn_id:
                    s = safe_txn_id(row.get(col, ''))
                    if s:
                        return s
            
            # Last resort: Try any column with just "UTR" and "NUMBER"
            for col in row.index:
                nc = norm(col)
                if 'utr' in nc and 'number' in nc:
                    s = safe_txn_id(row.get(col, ''))
                    if s:
                        return s
            
            return ''
        
        def clean_amt(v):
            if pd.isna(v) or v is None or v == '':
                return None
            try:
                s = str(v)
                s = re.sub(r'[^\d\.\-]', '', s)
                return float(s) if s else None
            except Exception:
                return None

        missing = [t for t in transactions if not (t.txn_id and str(t.txn_id).strip())]
        if missing:
            by_upload = {}
            for t in missing:
                if t.upload_id:
                    by_upload.setdefault(t.upload_id, []).append(t)
            for upload_id, txns in by_upload.items():
                up = UploadedFile.query.get(upload_id)
                if not up or not up.data:
                    continue
                try:
                    xls = pd.ExcelFile(io.BytesIO(up.data))
                    if 'Money Transfer to' not in xls.sheet_names:
                        continue
                    df = pd.read_excel(xls, sheet_name='Money Transfer to')
                    utr2_col = find_utr2_column(df.columns)
                    
                    # Print column info for debugging
                    print(f"Excel columns: {list(df.columns)}")
                    print(f"Detected UTR2 column: {utr2_col}")
                    
                    df_map = {}
                    df_rows = []
                    
                    # Build map and also store rows for fuzzy matching
                    for _, r in df.iterrows():
                        acc = str(r.get('Account No', '')).strip()
                        date = str(r.get('Transaction Date', '')).strip()
                        amt = clean_amt(r.get('Transaction Amount'))
                        txid = get_txn_id_from_df_row(r, utr2_col)
                        
                        if acc and date and amt is not None:
                            df_rows.append({
                                'acc': acc,
                                'date': date,
                                'amt': amt,
                                'txid': txid if txid else '',
                                'full_row': r
                            })
                            # Exact match key
                            if txid:
                                df_map[(acc, date, amt)] = txid
                    
                    print(f"Found {len(df_rows)} rows in Excel with txn data")
                    
                    # Try to match transactions
                    for t in txns:
                        key = (t.to_account or '', t.txn_date or '', float(t.amount) if t.amount is not None else None)
                        
                        # Try exact match first
                        if key in df_map:
                            t.txn_id = df_map[key]
                            print(f"Exact match found for {t.to_account}: {t.txn_id}")
                            continue
                        
                        # Try fuzzy matching: account + date match with amount tolerance
                        found = False
                        to_acc = t.to_account or ''
                        txn_date = t.txn_date or ''
                        txn_amt = float(t.amount) if t.amount is not None else None
                        
                        for excel_row in df_rows:
                            # Account and date must match exactly
                            if excel_row['acc'] == to_acc and excel_row['date'] == txn_date:
                                # Amount should be very close (within 0.01)
                                if txn_amt is not None and excel_row['amt'] is not None:
                                    if abs(txn_amt - excel_row['amt']) < 0.01 and excel_row['txid']:
                                        t.txn_id = excel_row['txid']
                                        print(f"Fuzzy match found for {to_acc}: {t.txn_id}")
                                        found = True
                                        break
                                elif excel_row['txid']:
                                    # If amount is None, match anyway if we have a txid
                                    t.txn_id = excel_row['txid']
                                    print(f"Partial match found for {to_acc}: {t.txn_id}")
                                    found = True
                                    break
                        
                        if not found and txns.index(t) < 3:  # Log first few unmatch to debug
                            print(f"No match found for txn: acc={to_acc}, date={txn_date}, amt={txn_amt}")
                    
                    db.session.commit()
                    print(f"Updated {len([t for t in txns if t.txn_id])} transactions with txn_id")
                except Exception as e:
                    print(f"Error processing missing txn_ids: {e}")
                    import traceback
                    traceback.print_exc()

        from_to_map = defaultdict(lambda: defaultdict(list))
        incoming_map = defaultdict(list)

        for t in transactions:
            key = (t.from_account, t.to_account, t.amount, t.txn_date, t.txn_id)
            if not any(txn['txn_id'] == t.txn_id for txn in from_to_map[t.from_account][t.to_account]):
                from_to_map[t.from_account][t.to_account].append({
                    'txn_id': t.txn_id,
                    'amount': t.amount,
                    'date': t.txn_date,
                    'ack_no': t.ack_no
                })
                incoming_map[t.to_account].append({
                    'from_account': t.from_account,
                    'amount': t.amount,
                    'date': t.txn_date,
                    'ack_no': t.ack_no,
                    'txn_id': t.txn_id,
                })

        from_layer_map = {t.from_account: t.layer for t in transactions if t.from_account}

        def build_hierarchy(rows):
            root = {'name': 'Flow', 'children': []}

            def find_node(n, target):
                if n['name'] == target:
                    return n
                for c in n.get('children', []):
                    found = find_node(c, target)
                    if found:
                        return found
                return None

            for t in rows:
                if t.layer == 1:
                    parent = next((c for c in root['children'] if c['name'] == t.from_account), None)
                    if not parent:
                        parent = {
                            'name': t.from_account,
                            'children': [],
                            'kyc_name': t.kyc_name,
                            'kyc_aadhar': t.kyc_aadhar,
                            'kyc_mobile': t.kyc_mobile,
                            'kyc_address': t.kyc_address,
                            'action': t.action_taken,
                        }
                        root['children'].append(parent)
                else:
                    parent = find_node(root, t.from_account)

                if parent:
                    existing = next((c for c in parent['children'] if c['name'] == t.to_account), None)
                    if not existing:
                        # ✅ calculate total amount of all transactions between parent → child
                        child = {
                            'name': t.to_account,
                            'children': [],
                            'layer': from_layer_map.get(t.to_account, t.layer),
                            'ack': t.ack_no,
                            'bank': t.bank_name,
                            'ifsc': t.ifsc_code,
                            'date': t.txn_date,
                            'txid': (
                                t.txn_id or next(
                                    (tx.get('txn_id') for tx in from_to_map[t.from_account][t.to_account] if tx.get('txn_id')),
                                    None
                                )
                            ),
                            'amt': str(t.amount),
                            'disputed': str(t.disputed_amount),
                            'action': t.action_taken,
                            'state': t.state if t.state and t.state != 'Unknown' else (t.ifsc_code or 'Unknown State'),
                            'atm_info': {
                                'atm_id': t.atm_id,
                                'amount': t.atm_withdraw_amount,
                                'date': t.atm_withdraw_date,
                                'location': t.atm_location
                            } if t.atm_id else None,
                            'cheque_info': {
                                'cheque_no': t.cheque_no,
                                'amount': t.cheque_withdraw_amount,
                                'date': t.cheque_withdraw_date,
                                'ifsc': t.cheque_ifsc
                            } if t.cheque_no else None,
                            'hold_info': {
                                'txn_id': t.put_on_hold_txn_id,
                                'amount': t.put_on_hold_amount,
                                'date': t.put_on_hold_date,
                                'court_order_date': t.court_order_date,
                                'refund_status': t.refund_status,
                                'refund_amount': t.refund_amount,
                            } if t.put_on_hold_txn_id else None,
                            'kyc_name': t.kyc_name,
                            'kyc_aadhar': t.kyc_aadhar,
                            'kyc_mobile': t.kyc_mobile,
                            'kyc_address': t.kyc_address,
                            # ✅ Keep all individual transactions for popup
                            'transactions_from_parent': from_to_map[t.from_account][t.to_account]
                        }
                        parent['children'].append(child)

            return root

        result = build_hierarchy(transactions)
        print(f"Built hierarchy with {len(result['children'])} root children")
        return jsonify(result)
    except Exception as e:
        print(f"Error processing graph data for ACK {ack_no}: {e}")
        return jsonify({'error': f'Error processing graph data: {str(e)}'}), 500

@app.route('/available_ack_nos')
def available_ack_nos():
    """Debug endpoint to list all available ACK numbers"""
    ack_nos = db.session.query(Transaction.ack_no).distinct().all()
    ack_list = [ack[0] for ack in ack_nos if ack[0]]
    return jsonify({'available_ack_nos': sorted(ack_list)})

@app.route('/statewise_summary/<ack_no>')
def statewise_summary(ack_no):
    try:
        # Check if we have any transactions with known states
        known_states_count = db.session.query(Transaction).filter(
            Transaction.ack_no == ack_no,
            Transaction.state.isnot(None),
            Transaction.state != 'Unknown'
        ).count()

        if known_states_count == 0:
            # If no known states, fetch synchronously for immediate response
            transactions_unknown = Transaction.query.filter(
                Transaction.ack_no == ack_no,
                (Transaction.state.is_(None) | (Transaction.state == 'Unknown')),
                Transaction.ifsc_code.isnot(None)
            ).all()

            if transactions_unknown:
                ifscs_to_fetch = {t.ifsc_code for t in transactions_unknown}
                ifsc_to_state = {}
                with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
                    future_to_ifsc = {executor.submit(get_state, ifsc): ifsc for ifsc in ifscs_to_fetch}
                    for future in concurrent.futures.as_completed(future_to_ifsc):
                        ifsc = future_to_ifsc[future]
                        try:
                            state = future.result()
                        except Exception as exc:
                            print(f'IFSC {ifsc} generated an exception: {exc}')
                            state = 'Unknown'
                        ifsc_to_state[ifsc] = state

                # Update the database with the fetched states (normalized to title case)
                for t in transactions_unknown:
                    if t.ifsc_code in ifsc_to_state:
                        t.state = ifsc_to_state[t.ifsc_code].title()
                db.session.commit()

        # Now use database aggregation for efficiency
        from sqlalchemy import func, distinct

        state_summaries = db.session.query(
            Transaction.state,
            func.count(Transaction.id).label('total_transactions'),
            func.sum(Transaction.amount).label('total_amount'),
            func.group_concat(distinct(Transaction.ifsc_code)).label('ifsc_codes')
        ).filter(
            Transaction.ack_no == ack_no,
            Transaction.state.isnot(None),
            Transaction.state != 'Unknown'
        ).group_by(Transaction.state).all()

        # Define regions
        regions = {
            'Southern': ['Tamil Nadu', 'Kerala', 'Karnataka', 'Andhra Pradesh', 'Telangana', 'Puducherry', 'Lakshadweep', 'Andaman and Nicobar Islands'],
            'Western': ['Maharashtra', 'Gujarat', 'Rajasthan', 'Goa', 'Daman and Diu', 'Dadra and Nagar Haveli'],
            'Eastern': ['West Bengal', 'Odisha', 'Bihar', 'Jharkhand', 'Assam', 'Arunachal Pradesh', 'Nagaland', 'Manipur', 'Mizoram', 'Tripura', 'Meghalaya', 'Sikkim'],
            'Northern': ['Jammu and Kashmir', 'Himachal Pradesh', 'Punjab', 'Chandigarh', 'Uttarakhand', 'Haryana', 'Delhi', 'Uttar Pradesh', 'Madhya Pradesh', 'Chhattisgarh', 'Ladakh']
        }

        # Convert to list
        summaries = []
        for summary in state_summaries:
            state, total_transactions, total_amount, ifsc_codes_str = summary
            ifsc_codes = sorted(ifsc_codes_str.split(',')) if ifsc_codes_str else []
            formatted_state = state.title() if state and state != 'Unknown' else state
            summaries.append({
                'state': formatted_state,
                'total_transactions': total_transactions,
                'total_amount': float(total_amount) if total_amount else 0.0,
                'ifsc_codes': ifsc_codes
            })

        # Group by regions
        regional_summaries = {region: [] for region in regions}
        other_summaries = []
        for summary in summaries:
            state = summary['state']
            placed = False
            for region, states in regions.items():
                if state in states:
                    regional_summaries[region].append(summary)
                    placed = True
                    break
            if not placed:
                other_summaries.append(summary)

        # Sort within each region by total_amount descending, except Southern which uses custom order
        southern_order = ['Tamil Nadu', 'Kerala', 'Karnataka', 'Andhra Pradesh', 'Telangana', 'Puducherry', 'Lakshadweep', 'Andaman and Nicobar Islands']
        for region in regional_summaries:
            if region == 'Southern':
                # Sort Southern by custom order, then by amount descending for ties
                regional_summaries[region].sort(key=lambda x: (southern_order.index(x['state']) if x['state'] in southern_order else len(southern_order), -x['total_amount']))
            else:
                regional_summaries[region].sort(key=lambda x: x['total_amount'], reverse=True)

        # Concatenate in order: Southern, Western, Eastern, Northern, then others
        result = (regional_summaries['Southern'] +
                  regional_summaries['Western'] +
                  regional_summaries['Eastern'] +
                  regional_summaries['Northern'] +
                  other_summaries)

        return jsonify(result)
    except Exception as e:
        print(f"Error in statewise_summary for {ack_no}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/put_on_hold_transactions/<ack_no>')
def put_on_hold_transactions(ack_no):
    """Return all put-on-hold transactions for a complaint."""
    try:
        hold_txns = Transaction.query.filter(
            Transaction.ack_no == ack_no.strip(),
            Transaction.put_on_hold_txn_id.isnot(None)
        ).all()

        response = []
        for t in hold_txns:
            response.append({
                'account_number': t.account_number or t.to_account,
                'bank_name': t.bank_name,
                # Branch name is not available in the stored data; keep placeholder
                'branch_name': None,
                'ifsc_code': t.ifsc_code,
                'amount': t.put_on_hold_amount,
                'layer': t.layer
            })

        return jsonify(response)
    except Exception as e:
        print(f"Error fetching hold transactions for {ack_no}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/state_transactions/<ack_no>/<state>')
def state_transactions(ack_no, state):
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    offset = (page - 1) * per_page

    # Use case-insensitive and trimmed comparison for state matching
    state_lower = state.strip().lower()

    # Get total count for this specific state
    total_count = Transaction.query.filter(
        Transaction.ack_no == ack_no,
        db.func.lower(db.func.trim(Transaction.state)) == state_lower
    ).count()

    # Query transactions for this state with pagination, sorting ATM transactions first
    transactions = Transaction.query.filter(
        Transaction.ack_no == ack_no,
        db.func.lower(db.func.trim(Transaction.state)) == state_lower
    ).order_by(Transaction.atm_id.isnot(None).desc()).offset(offset).limit(per_page).all()

    state_transactions = []
    for t in transactions:
        # Case-insensitive comparison for state matching
        if t.state and t.state.lower() == state.lower():
            # Determine transaction type
            if t.atm_id is not None:
                txn_type = 'ATM Withdrawal'
                txn_amt = t.atm_withdraw_amount
                txn_id = 'N/A'
            elif t.cheque_no is not None:
                txn_type = 'Cheque Withdrawal'
                txn_amt = t.cheque_withdraw_amount
                txn_id = 'N/A'
            elif t.put_on_hold_txn_id is not None:
                txn_type = 'Put on Hold'
                txn_amt = t.put_on_hold_amount
                txn_id = 'N/A'
            else:
                txn_type = 'Account Transfer'
                txn_amt = str(t.amount)
                txn_id = t.txn_id

            state_transactions.append({
                'ack_no': t.ack_no,
                'account_name': t.account_number,
                'bank_name': t.bank_name,
                'amount': txn_amt,
                'ifsc_code': t.ifsc_code,
                'date': t.txn_date or 'N/A',
                'transaction_type': txn_type,
                #'status': t.action_taken or 'N/A',
                'transaction_id': txn_id,
                'layer' : t.layer or 'N/A' #added by D
            })

    return jsonify({
        'transactions': state_transactions,
        'total_count': total_count,
        'page': page,
        'per_page': per_page,
        'total_pages': (total_count + per_page - 1) // per_page
    })

@app.route('/save_kyc', methods=['POST'])
def save_kyc():
    if session.get('role') in VIEW_ONLY_ROLES:
        return jsonify({"status": "error", "message": "View-only users cannot edit KYC"}), 403
    data = request.get_json()
    txn_id = data.get('txn_id')

    txn = Transaction.query.filter_by(txn_id=txn_id).first()
    if txn:
        txn.kyc_name = data.get('name')
        txn.kyc_aadhar = data.get('aadhar')
        txn.kyc_mobile = data.get('mobile')
        txn.kyc_address = data.get('address')
        db.session.commit()
        print("Got KYC Save Request:", data)
        print("Transaction Found:", txn is not None)
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Transaction not found"})


@app.route('/save_hold_refund', methods=['POST'])
def save_hold_refund():
    """Save court order / refund details for a put-on-hold transaction."""
    if session.get('role') in VIEW_ONLY_ROLES:
        return jsonify({"status": "error", "message": "View-only users cannot edit refund details"}), 403

    data = request.get_json() or {}
    ack_no = (data.get('ack_no') or '').strip()
    hold_txn_id = (data.get('hold_txn_id') or '').strip()

    if not ack_no or not hold_txn_id:
        return jsonify({"status": "error", "message": "Missing required identifiers"}), 400

    txn = Transaction.query.filter_by(
        ack_no=ack_no,
        put_on_hold_txn_id=hold_txn_id
    ).first()

    if not txn:
        return jsonify({"status": "error", "message": "Put-on-hold transaction not found"}), 404

    txn.court_order_date = (data.get('court_order_date') or '').strip() or None
    txn.refund_status = (data.get('refund_status') or '').strip() or None

    refund_amount_raw = data.get('refund_amount')
    try:
        txn.refund_amount = float(refund_amount_raw) if refund_amount_raw not in (None, '') else None
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Invalid refund amount"}), 400

    db.session.commit()

    return jsonify({"status": "success"})

@app.route('/view_all_complaints')
def view_all_complaints():
    try:
        log_usage('view_all_complaints')
    except Exception as e:
        print(f"UsageLog view_all_complaints error: {e}")
    complaints = UploadedFile.query.order_by(UploadedFile.upload_time.desc()).all()

    # Build a mapping of filename → list of distinct ACK numbers across all uploads
    filename_ack_rows = (
        db.session.query(UploadedFile.filename, Transaction.ack_no)
        .join(Transaction, Transaction.upload_id == UploadedFile.id)
        .filter(Transaction.ack_no.isnot(None))
        .distinct()
        .all()
    )

    filename_to_acks = {}
    for fname, ack in filename_ack_rows:
        if not ack:
            continue
        filename_to_acks.setdefault(fname, set()).add(ack)

    # Convert upload_time to IST (UTC+5:30) and attach ACK numbers by filename
    for c in complaints:
        if c.upload_time:
            c.upload_time = c.upload_time.replace(tzinfo=timezone.utc).astimezone(
                timezone(timedelta(hours=5, minutes=30))
            )

        ack_set = filename_to_acks.get(c.filename, set())
        c.ack_nos = sorted(list(ack_set)) if ack_set else []
        print(f"File: {c.filename}, ID: {c.id}, ACK numbers: {c.ack_nos}")

    # Deduplicate by ACK number (keep the latest upload per ACK based on ordering)
    seen_acks = set()
    unique_complaints = []
    for c in complaints:
        ack_value = c.ack_nos[0] if c.ack_nos else None
        if ack_value and ack_value in seen_acks:
            continue
        if ack_value:
            seen_acks.add(ack_value)
        unique_complaints.append(c)

    return render_template("view_all_complaints.html", complaint_data=unique_complaints)


@app.route('/view_officers')
def view_officers():
    if 'username' not in session or session.get('role') != 'Admin':
        return redirect('/login')

    # Get all officers
    officers = User.query.filter_by(role='Investigative Officer').all()

    # For each officer, count uploaded files
    officer_data = []
    for officer in officers:
        computed_upload_count = UploadedFile.query.filter_by(uploader=officer.username).count()
        upload_count = officer.manual_upload_count if officer.manual_upload_count is not None else computed_upload_count
        officer_data.append({
            'username': officer.username,
            'role': officer.role,
            'upload_count': upload_count,
            'computed_upload_count': computed_upload_count,
            'manual_upload_count': officer.manual_upload_count,
            'name': officer.name,
            'rank': officer.rank,
            'email': officer.email
        })

    return render_template('view_officers.html', officers=officer_data)

@app.route('/update_officer', methods=['POST'])
def update_officer():
    if 'username' not in session or session.get('role') != 'Admin':
        flash('Access Denied!')
        return redirect(url_for('login'))

    username = (request.form.get('username') or '').strip()
    if not username:
        flash('Invalid request.')
        return redirect(url_for('view_officers'))

    user = User.query.filter_by(username=username).first()
    if not user:
        flash('Officer not found.')
        return redirect(url_for('view_officers'))

    # Only allow editing investigative officers via this view
    if user.role != 'Investigative Officer':
        flash('Only Investigative Officers can be edited here.')
        return redirect(url_for('view_officers'))

    # Update editable fields (keep it minimal)
    user.name = (request.form.get('name') or '').strip() or None
    user.rank = (request.form.get('rank') or '').strip() or None
    user.email = (request.form.get('email') or '').strip() or None

    manual_upload_count_raw = (request.form.get('manual_upload_count') or '').strip()
    if manual_upload_count_raw == '':
        user.manual_upload_count = None
    else:
        try:
            user.manual_upload_count = int(manual_upload_count_raw)
        except ValueError:
            flash('No. of Files Uploaded must be a number (or leave blank).')
            return redirect(url_for('view_officers'))

    db.session.commit()
    flash(f'Officer {username} updated successfully.')
    return redirect(url_for('view_officers'))


@app.route('/delete_officer', methods=['POST'])
def delete_officer():
    if 'username' not in session or session.get('role') != 'Admin':
        flash('Access Denied!')
        return redirect(url_for('login'))

    username = request.form.get('username')
    if not username:
        flash('Invalid request.')
        return redirect(url_for('view_officers'))

    user = User.query.filter_by(username=username).first()
    if not user:
        flash('Officer not found.')
        return redirect(url_for('view_officers'))

    if user.role == 'Admin':
        flash('Cannot delete admin user.')
        return redirect(url_for('view_officers'))

    db.session.delete(user)
    db.session.commit()    
    flash(f'Officer {username} deleted successfully.')
    return redirect(url_for('view_officers'))


@app.route('/view_analytics')
# @login_required
def view_analytics():
    try:
        log_usage('view_analytics')
    except Exception as e:
        print(f"UsageLog view_analytics error: {e}")
    # Total unique filenames uploaded (regardless of duplicates)
    total_uploaded_files = db.session.query(func.count(func.distinct(UploadedFile.filename))).scalar()

    # Total transactions
    total_txns = db.session.query(func.count(Transaction.id)).scalar()

    # Total amount
    total_amount = db.session.query(func.sum(Transaction.amount)).scalar() or 0

    # Transactions per file
    txns_per_file = db.session.query(
        UploadedFile.filename,
        func.count(Transaction.id).label("txn_count")
    ).join(Transaction, Transaction.upload_id == UploadedFile.id)\
     .group_by(UploadedFile.filename)\
     .all()

    # Uploads by investigative officers
    officer_uploads = db.session.query(
        User.username,
        func.count(UploadedFile.id).label('upload_count')
    ).join(UploadedFile, UploadedFile.uploader == User.username)\
     .filter(User.role == 'Investigative Officer')\
     .group_by(User.username)\
     .all()

    # Frequent IFSC codes
    frequent_ifsccodes = db.session.query(
        Transaction.ifsc_code,
        func.count(Transaction.id).label('count')
    ).group_by(Transaction.ifsc_code)\
     .order_by(desc('count'))\
     .limit(5)\
     .all()

    return render_template("view_analytics.html",
        total_uploaded_files=total_uploaded_files,
        total_txns=total_txns,
        total_amount=total_amount,
        txns_per_file=txns_per_file,
        officer_uploads=officer_uploads,
        frequent_ifsccodes=frequent_ifsccodes
    )
@app.route('/download_logs')
def download_logs():
    if 'username' not in session:
        return redirect('/login')
    try:
        now = datetime.now(timezone.utc)
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end_of_day = start_of_day + timedelta(days=1)
        logs = UsageLog.query.filter(UsageLog.timestamp >= start_of_day, UsageLog.timestamp < end_of_day).order_by(UsageLog.timestamp.asc()).all()
        lines = []
        for l in logs:
            ts_ist = l.timestamp.replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=5, minutes=30)))
            ts_str = ts_ist.strftime('%Y-%m-%d %H:%M:%S')
            u = l.username or ''
            r = l.role or ''
            a = l.action or ''
            f = l.filename or ''
            an = l.ack_no or ''
            lines.append(f"{ts_str} | {u}({r}) | {a} | {f} | {an}")
        content = "\n".join(lines) if lines else "No logs for today."
        buf = io.BytesIO(content.encode('utf-8'))
        fname = f"usage_logs_{start_of_day.astimezone(timezone(timedelta(hours=5, minutes=30))).strftime('%Y-%m-%d')}.txt"
        log_usage('download_logs')
        return send_file(buf, mimetype='text/plain', as_attachment=True, download_name=fname)
    except Exception as e:
        return f"Failed to generate logs: {e}", 500

@app.route('/delete_complaint', methods=['POST'])
def delete_complaint():
    if session.get('role') in VIEW_ONLY_ROLES:
        flash("View-only users cannot delete complaints.", "warning")
        return redirect('/admin_dashboard')
    ack_no = request.form.get('ack_no', '').strip()

    if not ack_no:
        flash("Please enter a valid ACK No.", "warning")
        return redirect('/admin_dashboard')

    # Get transactions with that ACK No
    txns_to_delete = Transaction.query.filter_by(ack_no=ack_no).all()

    if not txns_to_delete:
        flash(f"No transactions found for ACK No: {ack_no}", "danger")
        return redirect('/admin_dashboard')

    try:
        # 🔁 Collect related uploaded_file.id (if needed)
        upload_ids = list({txn.upload_id for txn in txns_to_delete if txn.upload_id})

        # ❌ Delete transactions
        for txn in txns_to_delete:
            db.session.delete(txn)

        # ❌ Optionally delete UploadedFile
        for uid in upload_ids:
            file = UploadedFile.query.get(uid)
            if file:
                db.session.delete(file)

        db.session.commit()
        flash(f"Deleted all transactions (and uploaded file) for ACK No: {ack_no}.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting complaint: {str(e)}", "danger")

    return redirect('/admin_dashboard')

@app.route('/admin/add_officer', methods=['GET', 'POST'])
# @login_required
def add_officer():
    if session.get('role') != 'Admin':  # FIXED: 'Admin' not 'admin'
        flash('Access Denied!')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Officer with that username already exists.')
            return redirect(url_for('add_officer'))

        new_officer = User(
            username=username,
            role='Investigative Officer'
        )
        new_officer.set_password(password)
        db.session.add(new_officer)
        db.session.commit()
        flash('Verification Officer added successfully.')
        return redirect(url_for('view_officers'))

    return render_template('add_officer.html')

@app.route('/submit_officer', methods=['POST'])
def submit_officer():
    name = request.form.get('name', '').strip()
    rank = request.form.get('rank', '').strip()
    email = request.form.get('email', '').strip()
    username = request.form['username'].strip()
    password = request.form['password'].strip()

    if not (name and rank and email and username and password):
        flash("All fields are required.", "warning")
        return redirect('/add_officer')

    existing = User.query.filter_by(username=username).first()
    if existing:
        flash("Username already exists.", "danger")
        return redirect('/add_officer')

    new_officer = User(
        username=username,
        role='Investigative Officer',
        name=name,
        rank=rank,
        email=email
    )
    new_officer.set_password(password)  # ✅ Use method, not direct assignment
    db.session.add(new_officer)
    db.session.commit()

    flash("Verification Officer added successfully!", "success")
    return redirect('/admin_dashboard')


with app.app_context():
    db.create_all()

    from werkzeug.security import generate_password_hash

    # ✅ Indentation correctly inside app_context
    if User.query.count() == 0:
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            role='Admin'
        )
        officer = User(
            username='officer',
            password_hash=generate_password_hash('officer123'),
            role='Investigative Officer'
        )
        db.session.add(admin)
        db.session.add(officer)
        db.session.commit()
        print("✅ Dummy users added to the database")


if __name__ == '__main__':
    app.run(debug=True)
