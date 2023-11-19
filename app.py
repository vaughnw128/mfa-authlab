from flask import Flask, render_template, redirect, url_for, request, json, flash, session
import requests
from flask_bootstrap import Bootstrap
from flask_toastr import Toastr

app = Flask(__name__)
toastr = Toastr(app)
app.secret_key = 'TAKANAKA'


@app.route('/login_2fa', methods=['GET', 'POST'])
def login_2fa():
    error = None
    if request.method == 'POST':
        username = request.args['username']
        otp = int(request.form.get("otp"))
        if otp is None:
            error = "Please enter a value for the OTP."
        else:
            resp = requests.post('http://192.168.157.10/validate/check', data={'user':username, 'pass':otp, 'type':'totp', 'serial':'TOTP00006F8E', 'realm':'defrealm'})
            resp = resp.json()

            if resp['result']['authentication'] == "ACCEPT":
                return redirect(url_for("profile", username=username))

    return render_template('login_2fa.html', error=error)


# Route for handling the login page logic
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        otp = request.form['otp']
        if username and password and otp:
            resp = requests.post('http://192.168.157.10/validate/check', data={'user':username, 'pass':otp, 'realm':'defrealm'})
            resp = resp.json()
            print(resp)
            if resp['result']['authentication'] == "ACCEPT":
                flash("Password reset succesfully.")
        else:
            error = 'Please supply credentials.'
    return render_template('reset_password.html', error=error, username=username)


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

# Route for handling the login page logic
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    if username and password:
        resp = requests.post('http://192.168.157.10/auth', data={'username':username, 'password':password, 'realm':'defrealm'})
        resp = resp.json()
        if resp['result']['status']:
            return redirect(url_for("login_2fa", username=username))


if __name__=='__main__':
    app.run(port="8080", host="0.0.0.0")