from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, request
from flask_jwt_extended import create_access_token, get_jwt_identity, _decode_jwt_from_request, verify_jwt_in_request, unset_access_cookies, jwt_required, JWTManager, set_access_cookies, get_jwt
import requests
import os
from dotenv import load_dotenv
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from functools import wraps

app = Flask(__name__)
load_dotenv()

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.secret_key = os.getenv("APP_SECRET_KEY")
jwt = JWTManager(app)

def redirect_if_jwt_invalid(view_function):
    @wraps(view_function)
    def wrapper(*args, **kwargs):
        # attempt to grab the jwt from request
        try:
            jwt_data = decode_jwt_from_request(request_type='access')
        except:
            jwt_data = None
        # if the grab worked and the identity key is in the dict then proceed
        if jwt_data and 'identity' in jwt_data:
            return view_function(*args, **kwargs)
        else:
            return redirect('index', code=302)

    return wrapper 

# Tokens expire after one hour, and are then unset after that interval requiring a relogin
@jwt.expired_token_loader
def expired_token_callback(callback, expired_token):
    response = redirect(url_for("index"))
    unset_access_cookies(response)
    flash("Your session has expired. Please re-authenticate", category="info")
    return response

@jwt.unauthorized_loader
def unauthorized_callback(callback):
    response = redirect(url_for("index"))
    flash("The JWT is inavlid. Please re-authenticate", category="warning")
    return response

@app.route('/logout', methods=['GET'])
@jwt_required(optional=True)
def logout():
    try:
        jwt = get_jwt()
        response = redirect(url_for("index"))
        unset_access_cookies(response)
        flash("Bye bye!", category="success")
        return response
    except Exception:
        flash("Bye bye!", category="success")
        return redirect(url_for("index"))

@app.route('/reset', methods=['POST'])
def reset():
    username = request.form['username']
    password = request.form['password']
    otp = request.form['otp']
    if username and password and otp:
        resp = requests.post('http://192.168.157.10/validate/check', data={'user':username, 'pass':otp, 'realm':'defrealm'})
        resp = resp.json()
        print(resp)
        try:
            if resp['result']['authentication'] == "ACCEPT":
                resp = requests.post('http://192.168.157.10/auth', data={'username':os.getenv("AUTH_ADMIN"), 'password':os.getenv("AUTH_PASSWORD"), 'realm':'defrealm'})
                if resp.status_code == 200:
                    resp = resp.json()
                    authorization = resp['result']['value']['token']
                    resp = requests.put('http://192.168.157.10/user', data={'user':username, 'password':password, 'realm':'defrealm', 'resolver':'defsqlresolver'}, headers={"Authorization": authorization})
                    flash("Password successfully reset", category="success")
                    return redirect(url_for("reset_password"))
            else:
                flash("Invalid TOTP", category="danger")
                response = redirect(url_for("reset_password"))
                return response
        except Exception:
            flash("Invalid TOTP or User", category="danger")
            response = redirect(url_for("reset_password"))
            return response
    else:
        flash("Please supply values for all fields", category="warning")
        response = redirect(url_for("reset_password"))
        return response
        
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
            flash("Invalid credentials.", category="danger")
            return redirect(url_for('index'))
    else:
        flash("Please supply values for all fields", category="warning")
        response = redirect(url_for("index"))
        return response
        

@app.route('/authenticate_totp', methods=['POST'])
@jwt_required()
def authenticate_totp():
    username = get_jwt_identity()['username']
    otp = request.form.get("otp")
    try:
        otp = int(otp)
    except Exception:
        otp = None
    
    if not otp:
        flash("Please enter a pin", category="warning")
        response = redirect(url_for("authenticate"))
        return response
    else:
        resp = requests.post('http://192.168.157.10/validate/check', data={'user': username, 'pass':otp, 'realm':'defrealm'})
        resp = resp.json()
        if resp['result']['authentication'] == "ACCEPT":
            response = redirect(url_for("profile"))
            access_token = create_access_token(identity={"username": username, "authenticated": True})
            set_access_cookies(response, access_token)
            return response
        else:
            flash("Invalid TOTP", category="danger")
            response = redirect(url_for("authenticate"))
            return response

@app.route('/reset_password', methods=['GET'])
def reset_password():
    return render_template('reset_password.html')

@app.route('/authenticate', methods=['GET'])
@jwt_required()
def authenticate():
    return render_template('authenticate.html')

@app.route('/', methods=['GET'])
@jwt_required(optional=True)
def index():
    identity = get_jwt_identity()
    if identity is not None:
        authenticated = identity['authenticated']

        if authenticated:
            return redirect(url_for("profile"))
    
    return render_template('index.html')

@app.route('/profile', methods=['GET'])
@redirect_if_jwt_invalid()
def profile():
    identity = get_jwt_identity()
    if identity is not None:
        authenticated = get_jwt_identity()['authenticated']

        if not authenticated:
            response = redirect(url_for("index"))
            unset_access_cookies(response)
            return response
        
        return render_template('profile.html')
    response = redirect(url_for("index"))

if __name__=='__main__':
    app.run(port="8080", host="0.0.0.0")