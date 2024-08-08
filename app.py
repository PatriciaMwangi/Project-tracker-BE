from flask import Flask, request, make_response, jsonify
from flask_restful import Api, Resource
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity, jwt_required
)
import os
from config import db, app, mail
from models import User, Project
from flask_mail import Message

# Configurations

app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "super-secret-key")
app.config['JWT_TOKEN_LOCATION'] = ['headers']
jwt = JWTManager(app)
api=Api(app)

@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()

# User registration
class UserRegistration(Resource):
  def post(self):
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    is_admin = data.get('is_admin')

    user = User.query.filter_by(email=email).first()

    if not user:
      try:
        user = User(
          username=username,
          email=email,
          is_admin=is_admin
        )
        user.password_hash = password
        db.session.add(user)
        db.session.commit()

        access_token = create_access_token(identity=user)
        return make_response({"user":user.to_dict(),'access_token': access_token},201)
      
      except Exception as e:
        return {'error': e.args}, 422

    else:
      return make_response({'error':"Email already registered, kindly log in"},401)  

api.add_resource(UserRegistration, '/register', endpoint='/register')  

# User login
class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(email=data.get('email')).first()
        if user:
            if user.authenticate(data.get('password')):
                access_token = create_access_token(identity=user)
                response = make_response({"user":user.to_dict(),'access_token': access_token},201)
                return response
            else:
                 return make_response({'error':"Incorrect password"},401)
        else:
             return make_response({'error':"Unauthorized"},401)
        
api.add_resource(Login,'/login',endpoint="login")   

class ProjectR(Resource):
   def post(self):
      data = request.get_json()
      print('Received Data',data)
      name=data['name']
      description=data['description']
      ghlink=data['ghlink']
      contributors=data['contributors'] 


      print("name", name)
      print("Descr", description)
      print("Glink", ghlink)
      print("COntributors", contributors)

      if not isinstance(data,dict):
          return {'error':'Invalid data format'},400
        
      try:
        new_project = Project(
          name=name,
          description=description,
          ghlink=ghlink,
          contributors=contributors
        )

        print("new poroject", new_project)

        db.session.add(new_project)
        db.session.commit()

        for email in contributors.values():
            send_invitation(email,name)

        
        return {'message': 'Project created successfully and emails sent'}, 201
      except KeyError as e:
            return {'error': f'Missing field: {str(e)}'}, 400
      except Exception as e:
            return {'error': str(e)}, 500
      
def send_invitation(email,project_name):
    try:
        msg = Message("You are invited to be a contributor!",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = f"Hello, you are invited to join the project '{project_name}'. Please sign up or login to participate."
        mail.send(msg)
        print(f"Email successfully sent to {email}")

    except Exception as e:
        # Handle the exception or log it
        print(f"Failed to send email to {email}: {str(e)}")

   
api.add_resource(ProjectR,'/projects')

@app.route('/')
def index():
    return 'Welcome to the Flask app!'

if __name__ == '__main__':
    app.run(port=5600,
            debug=True
            )