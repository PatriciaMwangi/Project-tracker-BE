import os
from dotenv import load_dotenv
load_dotenv() 
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from sqlalchemy import MetaData
from flask_restful import Api
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_mail import Mail

app = Flask(__name__)

app.secret_key = b'Y\xf1Xz\x00\xad|eQ\x80t \xca\x1a\x10K'
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json.compact = False

#email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'patricia.mwangi@student.moringaschool.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'fahw wiok ilpn eupj')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

metadata = MetaData()

bcrypt = Bcrypt(app)

api = Api(app)
CORS(app)