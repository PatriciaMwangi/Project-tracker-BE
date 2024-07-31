from flask import Flask, request, make_response, jsonify
from flask_restful import Api, Resource
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity, jwt_required
)
import os
from config import db, app
from models import User

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

if __name__ == '__main__':
    app.run(port=5600,
            debug=True
            )