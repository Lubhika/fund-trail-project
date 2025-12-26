from flask import Flask
from flask_migrate import Migrate
from models import db

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root%40123@localhost/fundtrail_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
migrate = Migrate(app, db)

with app.app_context():
    from alembic.config import Config
    from alembic import command
    config = Config('migrations/alembic.ini')
    config.set_main_option('script_location', 'migrations')
    command.upgrade(config, 'head')
    print("Database migration completed successfully")
