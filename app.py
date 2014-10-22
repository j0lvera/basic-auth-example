import bottle
from bottle import Bottle, route, run, response, install, request, abort, parse_auth, auth_basic, error, hook
from passlib.hash import pbkdf2_sha256
from redis import StrictRedis as Redis
from hashids import Hashids
from random import randint

# Redis 
redis = Redis(host='localhost', port=6379, db=0)

# Mongo
from bson import ObjectId
from bson.json_util import dumps

DATABASE_HOST = 'localhost'
DATABASE_NAME = 'db'
DATABASE_PORT = 27017

import pymongo
from pymongo import Connection

connection = Connection(DATABASE_HOST, DATABASE_PORT)
db = connection[DATABASE_NAME]
users = db.users

# Methods
def generate_token(email, password):
    salt = str(email + password) 
    print "salt: " + salt

    # Hashids config
    hashids = Hashids(salt=salt, min_length="16")

    # Incremental id
    incr = users.find_one({'email': email})['_id']
    print "userid: " + str(incr)

    # Generating token
    token = hashids.encrypt(incr, randint(0, incr)) 
    print "token : " + str(token)
    return token

def save_token(email, token):
    user_id = "token:" + email
    redis.set(user_id, token)
    redis.expire(user_id, 86400)
    print "token: " + token + ", from: " + str(email) + " saved on redis db"

def get_get(name, default=''):
    return request.GET.get(name, default).strip()

def post_get(name, default=''):
    return request.POST.get(name, default).strip()

def hash_pass(password):
    return pbkdf2_sha256.encrypt(password, rounds=8000, salt_size=16)

def check_pass(email, password):
    print email
    print password
    password_hashed = users.find_one({'email': email})['password']
    print password_hashed
    print pbkdf2_sha256.verify(password, password_hashed)
    return pbkdf2_sha256.verify(password, password_hashed)

# Enable cors decorator
def enable_cors(fn):
    def _enable_cors(*args, **kwargs):
        # set CORS headers
        response.headers['Access-Control-Allow-Origin'] = 'http://localhost:9000'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Origin, Accept, Content-Type, X-Requested-With, X-CSRF-Token, Authorization'
        response.headers['Access-Control-Allow-Credentials'] = True

        if bottle.request.method != 'OPTIONS':
            # actual request; reply with the actual response
                return fn(*args, **kwargs)

    return _enable_cors

@route('/', method=['OPTIONS', 'GET'])
def hello():
    response.headers['Content-type'] = 'application/json'
    return { 'yo': 'sap' } 

@route('/api/token/', method=['OPTIONS', 'GET'])
@enable_cors
@auth_basic(check_pass)
def get_token():
    print request.headers.get('Authorization')
    return {200: 'yo'}

@route('/api/user/', method=['OPTIONS', 'POST'])
@enable_cors
def create():
    email = post_get('email')
    password = post_get('password')
    print (email is None)
    print (password is None)
    if (email == '') or (password == ''):
        abort(401, 'Missing Arguments') # Missing arguments
    elif users.find_one({'email': email}) is not None: # look for the username
        abort(400, 'Existing User') # Existing user
    else:
        password_hashed = hash_pass(password)
        users.insert({'_id': users.find().count() + 1, 'email': email, 'password': password_hashed})
        token = generate_token(email, password_hashed)
        save_token(email, token)

@route('/api/users/', method='GET')
@enable_cors
def show():
    result = users.find()
    return dumps(result)

@error(400)
@enable_cors
def mistake400(code):
    return "Existing User"

@error(401)
@enable_cors
def mistake401(code):
    return "Missing Arguments"

run(host='0.0.0.0', port='8080', reloader=True, debug=True)
