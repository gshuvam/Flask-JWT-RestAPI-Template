import json
from operator import index
from urllib import response
from xml.dom import NoModificationAllowedErr
from package import app, db
from flask import jsonify, make_response, request
from uuid import uuid1
from package.models import User
from package.helper import genHashedPwd, verifyPwd
import jwt
import datetime
from functools import wraps




def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'access-token' in request.headers:
            token = request.headers['access-token']
        if not token:
            return jsonify({'Message' : 'Token is missing!'})
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = User.query.filter_by(id = data['user_id']).first()
        except:
            return jsonify({'Message' : 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated



@app.route("/")
def home():
    return {"MSG": "Hello"}


@app.route("/login", methods=['GET', 'POST'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response("Invalid username or password!", 401, {'WWW-Authenticate' : 'Basic realm="Login Required!"'})
    user = User.query.filter_by(email=auth.username).first()
    if not user:
        return make_response("Invalid username or password!", 401, {'WWW-Authenticate' : 'Basic realm="Login Required!"'})
    if verifyPwd(auth.password, user.password):
        payload = jwt.encode({'user_id' : user.id, 'exp' : datetime.datetime.now() + datetime.timedelta(minutes=30)}, app.config["SECRET_KEY"])
        return jsonify({'token' : payload})
    return make_response("Invalid username or password!", 401, {'WWW-Authenticate' : 'Basic realm="Login Required!"'})


@app.route("/user/<string:id>", methods=['GET'])
@token_required
def getUser(current_user, id):
    if id.lower() == "all":
        if not current_user.admin:
            return jsonify({"Message" : "Unauthorized!"}), 401
        users = User.query.all()
        if not users:
            return jsonify({"Message": "No users found!"}), 404
        dic = {}
        index = 0
        for user in users:
            temp = {}
            temp["id"] = user.id
            temp["Name"] = user.name
            temp["Email"] = user.email
            temp["Admin"] = user.admin
            dic[index] = temp
            index += 1
        return dic
    if not current_user.admin and id != current_user.id:
        return jsonify({"Message" : "Unauthorized!"}), 401
    user = User.query.filter_by(id=id).first()
    if not user:
        return jsonify({"Message": "User not found!"}), 404
    dic = {}
    dic["id"] = user.id
    dic["Name"] = user.name
    dic["Email"] = user.email
    dic["Admin"] = user.admin
    return dic


@app.route("/user", methods=['POST'])
@token_required
def createUser(current_user):
    if not current_user.admin:
        return jsonify({"Message" : "Unauthorized!"}), 401
    response = request.json
    name = response['name']
    email = response['email']
    try:
        if not User.query.filter_by(email=email).first():
            password = genHashedPwd(response['password'])
            id = uuid1().hex
            admin = response['admin']
            user = User(id=id, name=name, email=email, admin=admin, password=password)
            db.session.add(user)
            db.session.commit()
            return jsonify({"Message" : f"User {name.split(' ')[0]} created successfully"})
        
        return jsonify({"Message" : f"User {email} already exists"}), 403

    except:
        return jsonify({"Message" : "Something went wrong! Try again later."}), 500



@app.route("/user/<string:userId>", methods=['PUT'])
@token_required
def updateUser(current_user, userId):
    if not current_user.admin and userId!= current_user.id:
        return jsonify({"Message" : "Unauthorized"}), 401
    user = User.query.filter_by(id=userId).first()
    if user:
        response = request.json
        name = None
        email = None
        password = None
        admin = None 
        print(response)
        if 'Name' in response and user.name != response['Name']:
            name = response['Name']
            user.name = name
        if 'Email' in response and user.email != response['Email']:
            email = response['Email']
            user.email = email
        if 'Password' in response:
            password = response['Password']
            user.password = genHashedPwd(password)
        if 'Admin' in response and user.admin != response['Admin']:
            admin = response['Admin']
            user.admin = admin
        if not name and not email and not password and admin == None:
            return jsonify({"Message": "Nothing to update!"}), 304
        db.session.add(user)
        db.session.commit()
        return jsonify({"Message" : f"User details updated to {user}"}), 200


@app.route("/user/<string:userId>", methods=['DELETE'])
@token_required
def deleteUser(current_user, userId):
    if not current_user.admin:
        return jsonify({"Message" : "Unauthorized!"})
    user = User.query.filter_by(id=userId).first()
    if not user:
        return make_response("User not found!")
    db.session.delete(user)
    db.session.commit()
    return jsonify({"Message" : f"User {user.email} deleted!"}), 200


@app.route("/test")
def test():
    return request.cookies.get('token')
