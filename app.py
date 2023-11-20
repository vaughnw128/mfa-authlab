from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, request, json
import requests
import os
from dotenv import load_dotenv

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import unset_access_cookies
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_jwt_extended import set_access_cookies

app = Flask(__name__)
load_dotenv()

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
app.secret_key = os.getenv("APP_SECRET_KEY")
jwt = JWTManager(app)

# Route for handling the login page logic
@app.route('/reset', methods=['GET', 'POST'])
def reset():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        otp = request.form['otp']
        if username and password and otp:
            resp = requests.post('http://192.168.157.10/validate/check', data={'user':username, 'pass':otp, 'realm':'defrealm'})
            resp = resp.json()
            if resp['result']['authentication'] == "ACCEPT":
                resp = requests.post('http://192.168.157.10/auth', data={'username':os.getenv("AUTH_ADMIN"), 'password':os.getenv("AUTH_PASSWORD"), 'realm':'defrealm'})
                if resp.status_code == 200:
                    resp = resp.json()
                    authorization = resp['result']['value']['token']
                    resp = requests.put('http://192.168.157.10/user', data={'user':username, 'password':password, 'realm':'defrealm', 'resolver':'defsqlresolver'}, headers={"Authorization": authorization})
                    return redirect(url_for("index"))

# Route for handling the login page logic
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    if username and password:
        resp = requests.post('http://192.168.157.10/auth', data={'username':username, 'password':password, 'realm':'defrealm'})
        resp = resp.json()
        if resp['result']['status']:
            response = redirect(url_for("authenticate"))
            access_token = create_access_token(identity={"username": username, "authenticated": False})
            set_access_cookies(response, access_token)
            return response
        else:
            flash("Invalid credentials.")
            return redirect(url_for('index'))

@app.route('/authenticate_totp', methods=['POST'])
@jwt_required()
def authenticate_totp():
    username = get_jwt_identity()['username']
    otp = int(request.form.get("otp"))
    if otp is None:
        error = "Please enter a value for the OTP."
    else:
        resp = requests.post('http://192.168.157.10/validate/check', data={'user': username, 'pass':otp, 'realm':'defrealm'})
        resp = resp.json()
        if resp['result']['authentication'] == "ACCEPT":
            print("worked!")
            response = redirect(url_for("profile"))
            access_token = create_access_token(identity={"username": username, "authenticated": True})
            set_access_cookies(response, access_token)
            return response

@app.route('/reset_password', methods=['GET'])
def reset_password():
    return render_template('reset_password.html')

@app.route('/authenticate', methods=['GET'])
@jwt_required()
def authenticate():
    return render_template('authenticate.html')

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    username = get_jwt_identity()['username']
    authenticated = get_jwt_identity()['authenticated']

    if not authenticated:
        response = redirect(url_for("index"))
        unset_access_cookies(response)
        return response
    
    return render_template('profile.html')

if __name__=='__main__':
    app.run(port="8080", host="0.0.0.0")