import bottle
from bottle import Bottle, route, run, response, install, request
from hashids import Hashids 
from passlib.hash import pbkdf2_sha256

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
def get_get(name, default=''):
	return request.GET.get(name, default).strip()

def post_get(name, default=''):
	return request.POST.get(name, default).strip()

def hash_pass(password):
	return pbkdf2_sha256.encrypt(password, rounds=8000, salt_size=16)

def check_pass(email, password):
	hashed = ''.join("""get password from db""")
	return pbkdf2_sha256.verify(password, hashed)

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
def login():
	email = post_get('email')
	password = post_get('password')
	password_hashed = hash_pass(password)

@route('/create', method=['OPTIONS', 'POST'])
@enable_cors
def create():
	response.headers['Content-type'] = 'application/json'
	email = post_get('email')
	password = post_get('password')
	password_hashed = hash_pass(password)
	print email
	print password 
	print password_hashed 
	users.insert({'email': email, 'password': password_hashed})
	return "User created"

@route('/show', method='GET')
@enable_cors
def show():
	return dumps(users.find())

run(host='0.0.0.0', port='8080', reloader=True)
