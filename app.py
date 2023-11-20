from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, request
from flask_jwt_extended import create_access_token, get_jwt_identity, verify_jwt_in_request, unset_access_cookies, jwt_required, JWTManager, set_access_cookies, get_jwt
import requests
import os
from dotenv import load_dotenv
from datetime import datetime
from datetime import timedelta
from datetime import timezone

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

# Using an `after_request` callback, we refresh any token that is within 30
# minutes of expiring. Change the timedeltas to match the needs of your application.
@app.after_request
@jwt_required(optional=True)
def refresh_expiring_jwts(response):
    try:
        now = datetime.now(timezone.utc)
        now = int(round(now.timestamp()))
        exp_timestamp = get_jwt()["exp"]
        if now > exp_timestamp:
            unset_access_cookies(response)
        return response
    except (RuntimeError, KeyError):
        return response
    except Exception:
        try:
            unset_access_cookies(response)
            return response
        except Exception:
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
        try:
            if resp['result']['authentication'] == "ACCEPT":
                resp = requests.post('http://192.168.157.10/auth', data={'username':os.getenv("AUTH_ADMIN"), 'password':os.getenv("AUTH_PASSWORD"), 'realm':'defrealm'})
                if resp.status_code == 200:
                    resp = resp.json()
                    authorization = resp['result']['value']['token']
                    resp = requests.put('http://192.168.157.10/user', data={'user':username, 'password':password, 'realm':'defrealm', 'resolver':'defsqlresolver'}, headers={"Authorization": authorization})
                    flash("Password successfully reset", category="success")
                    return redirect(url_for("index"))
        except Exception:
            flash("Invalid TOTP or User", category="danger")
            response = redirect(url_for("reset_password"))
            return response
        else:
            flash("Invalid TOTP", category="danger")
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
@jwt_required()
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