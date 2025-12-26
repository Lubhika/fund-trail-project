from app import app
from models import db, User

with app.app_context():
    db.create_all()
    admin = User(username='admin', role='Admin')
    admin.set_password('admin123')
    
    officer = User(username='officer', role='Investigative Officer')
    officer.set_password('Officer123')
    
    db.session.add(admin)
    db.session.add(officer)
    db.session.commit()
    print("Users created successfully.")
