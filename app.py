import bottle
from bottle import Bottle, route, run, response, install, request, abort, parse_auth, auth_basic, error, hook
from passlib.hash import pbkdf2_sha256, md5_crypt
from redis import StrictRedis as Redis
from itsdangerous import JSONWebSignatureSerializer as Sign
from hashids import Hashids
from random import randint

USER_ID_SALT = 'JtuD-wTBex24zec7 M67SZT6E6SjmiC TciddY6tE6-yhYmRoBDzeMMH5xUB2kExCzem7tPU9j9nopDva-nddQggyLuFX_c_4edXZTF9ueUKX-vp2j27-zvfTC5fs'
TOKEN_SALT = 'yVnWkuwcGUXq9vggQtY_e4thKmadeTiLAouTQ9m 7 mA4H 8pvtHsqiP_Q8xapTLehxjT9iJ3PNuhK2k4_fvx8j_We_D_Vu-edyS7GBaUgpU_vmSMxtysSohBdCwM'
SIGN_SALT = 'pEoBD9CAbA_5ijkok-wCGhRqT 9yfQJzB4mP-TFdKczG2UJoLa4vzmoh-2LXY8nZR5_JhNZwfAxequoS-5XSYCpg m9RiUCFLKxNN2ji82ni-H7PRB ygwjw37pNZ'

# Itsdangerous setup
s = Sign(SIGN_SALT)

# Redis Setup
redis = Redis(host='localhost', port=6379, db=0)

# Mongo Setup
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
def incr():
    return users.find().count() + 1

def generate_token(email, password):
    # TODO
    # Change Hashids for md5_crypt
    # Separate crypt setup logic from this function
    salt = str(email + password) 
    hashids = Hashids(salt=salt, min_length="82") # Hashids config
    incr_id = incr() # Incremental id
    token = hashids.encrypt(incr_id, randint(0, incr_id)) # Generate token
    return token

def save_token(email, token):
    user_id = "token:" + email
    redis.set(user_id, token)
    redis.expire(user_id, 86400)

def get_get(name, default=''):
    return request.GET.get(name, default).strip()

def post_get(name, default=''):
    return request.POST.get(name, default).strip()

def hash_pass(password):
    return pbkdf2_sha256.encrypt(password, rounds=8000, salt_size=16)

def check_pass(email, password):
    password_hashed = users.find_one({'email': email})['password']
    return pbkdf2_sha256.verify(password, password_hashed)

def check_token(unused, token):
    token_unsigned = s.loads(token)['token']
    id, tkn = token_unsigned.split(':',1)
    try:
        email = users.find_one({'_id': id})['email']
        token_stored = redis.get('token:' + email)
        return token_stored == tkn
    except:
        return "User not found"

def gen_id(id, salt):
    hashids = Hashids(salt=salt, min_length=16)
    return hashids.encrypt(id)

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

@route('/api/test/', method=['OPTIONS', 'GET'])
@enable_cors
@auth_basic(check_token)
def test():
    auth = request.headers.get('Authorization')
    email, password = parse_auth(auth)
    print email
    print password
    return {'email': email, 'password': password}

@route('/api/token/', method=['OPTIONS', 'GET'])
@enable_cors
@auth_basic(check_pass)
def get_token():
    auth = request.headers.get('Authorization')
    email, password = parse_auth(auth)
    id = users.find_one({'email': email})['_id']
    token_server = generate_token(email, password)
    print "token server: " + token_server
    save_token(email, token_server)
    token_client = s.dumps({'token': id + ":" + token_server})
    print "token client: " + token_client
    return {'token': token_client}

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
        id = gen_id(users.find().count() + 1, USER_ID_SALT)
        password_hashed = hash_pass(password)
        users.insert({'_id': id, 'email': email, 'password': password_hashed, 'role': 'user'})
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
