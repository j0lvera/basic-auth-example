import bottle
from bottle import Bottle, route, run, response, install, request, abort, parse_auth, auth_basic
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
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
    password_hashed = ''.join(users.find({'email': email})['password'])
    return pbkdf2_sha256.verify(password, password_hashed)

# def check_token(email, token):

# Enable cors decorator
def enable_cors(fn):
    def _enable_cors(*args, **kwargs):
        # set CORS headers
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Origin, Accept, Content-Type, X-Requested-With, X-CSRF-Token'

        if bottle.request.method != 'OPTIONS':
            # actual request; reply with the actual response
                return fn(*args, **kwargs)

    return _enable_cors


@route('/', method=['OPTIONS', 'GET'])
@enable_cors
def hello():
    response.headers['Content-type'] = 'application/json'
    return { 'yo': 'sap' } 

@route('/login', method='POST')
@enable_cors
@auth_basic(check_pass)
def login():
    return { 'token': 'figure out how to create a token' }

@route('/signup', method=['OPTIONS', 'POST'])
@enable_cors
def create():
    email = post_get('email')
    password = post_get('password')
    if email is None or password is None:
        abort(401, "Access Denied") # missing arguments
    if users.find_one({'email': email}) is not None: # look for the username
        abort(400, "Existing User") #existing user
    password_hashed = hash_pass(password)
    users.insert({'_id': users.find().count() + 1, 'email': email, 'password': password_hashed})
    token = generate_token(email, password_hashed)
    save_token(email, token)
    return {'token': token}

@route('/show', method='GET')
@enable_cors
def show():
    # result = users.find_one({'email': 'thinkxl@gmail.com'})['password']
    result = users.find()
    # result = users.find_one({'email': 'thinkxl@gmail.com'})['_id']

    return dumps(result)

run(host='0.0.0.0', port='8080', reloader=True)
