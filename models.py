from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates
from config import db, bcrypt
from datetime import datetime
import re


# User model
class User(db.Model, SerializerMixin):
  __tablename__ = 'users'

  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String, unique=True, nullable=False)
  email = db.Column(db.String, unique=True, nullable=False)
  _password_hash = db.Column(db.String, nullable=False)
  is_admin = db.Column(db.Boolean, default=False)

  @hybrid_property
  def password_hash(self):
      raise AttributeError('Password is not a readable attribute')
  
  @password_hash.setter
  def password_hash(self, password):
      password_hash = bcrypt.generate_password_hash(password.encode("utf-8"))
      self._password_hash = password_hash.decode("utf-8")

  def authenticate(self, password):
    return bcrypt.check_password_hash(self._password_hash, password.encode("utf-8"))  

class Project(db.Model,SerializerMixin):
  __tablename__='projects'
  id = db.Column(db.Integer,primary_key=True)
  name = db.Column(db.String,nullable=False)  
  description =db.Column(db.String,nullable=False)
  created_at = db.Column(db.DateTime,default=datetime.now)
  ghlink = db.Column(db.String,nullable=False)
  contributors = db.Column(db.String,nullable=False)
    
     