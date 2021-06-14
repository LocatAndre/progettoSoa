import functools
import onetimepass
import pyqrcode
from io import BytesIO
import os
import base64
from datetime import datetime
from ast import literal_eval
import jwt


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
    abort,
    make_response
)

from werkzeug.security import (
    check_password_hash,
    generate_password_hash
)

from .db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

def controllo_token(*token):
    date = datetime.now().timestamp()
    for t in token:
        if t['iss'] == 'https://localhost:9001/' and float(t['iat']) < float(date) and float(t['exp']) >= float(date):
            return True
        else:
            return False

@bp.route('/login')
def login():
    return render_template('site/login.html')

@bp.route('/login/otp')
def otp_page():
    return render_template('site/otp.html')

@bp.route('/login/otp/checkOtp', methods=['GET','POST'])
def check_otp():
    email = session.get('mail')
    otp = request.form.get('otp')

    db = get_db()
    error = None
    user = db.execute('SELECT * FROM user WHERE email = ?',
                      (email,)).fetchone()
    
    if not onetimepass.valid_totp(otp, user['otpSecret']):
        error = 'OTP errato' + otp
        return redirect(url_for('auth.otp_page'))
    else:
        session['user_id'] = user['id']
        return redirect(url_for('site.index'))

@bp.route('/login/checkUser', methods=['POST'])
def checkUser():
    email = request.form.get('email')
    password = request.form.get('password')

    db = get_db()
    error = None
    user = db.execute('SELECT * FROM user WHERE email = ?',
                      (email,)).fetchone()

    if user is None:
        error = 'Mail non presente'
    elif not check_password_hash(user['password'], password):
        error = 'Pasword errata'
    elif user['token_required'] != 0:
        error = 'Account proveniente da un oAuth server'
    if error is None:
        # pulisce le sessioni precednti
        session.clear()
        # crea la sessione corrente
        session['user_id'] = user['id']
        session['mail'] = email
        return redirect(url_for('auth.otp_page'))     

    session.clear()
    flash(error)
    return redirect(url_for('auth.login'))


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('site.index'))


@bp.route('/register/checkregister', methods=['POST'])
def checkregister():
    username = request.form['username']
    password1 = request.form['password1']
    password2 = request.form['password2']
    email = request.form['email']

    # Segreto casuale per OTP
    otpSecret = base64.b32encode(os.urandom(10)).decode('utf-8')

    db = get_db()
    error = None

    if not username or not password1 or not password2 or not email:
        error = 'Campi mancanti'
    elif db.execute('SELECT id FROM user WHERE email = ?', (email,)
                    ).fetchone() is not None:
        error = '{} è già iscritto.'.format(username)
    elif password1 != password2:
        error = 'Le 2 password non coincidono'
    elif password1 == password1 and len(password1) < 8:
        error = 'Password troppo fragile'

    if error is None:
        db.execute('INSERT INTO user (email, username, password, otpSecret) VALUES (?, ?, ?, ?)',
                   (email, username, generate_password_hash(password1), otpSecret)
                   )
        db.commit()
        session['mail'] = email
        return redirect(url_for('auth.two_factor_setup'))

    flash(error)
    return redirect(url_for('auth.register'))


@bp.route('/register')
def register():
    return render_template('site/register.html')

@bp.route('/twofactor')
def two_factor_setup():
    if 'mail' not in session:
        return redirect(url_for('site.index'))

    db = get_db()
    user = db.execute('SELECT * FROM user WHERE  email= ?',
                      (session['mail'],)).fetchone()
    if user is None:
        return redirect(url_for('site.index'))

    session['user_id'] = user['id']
    return render_template('site/2fa.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@bp.route('/qrcode')
def qrcode():

    if 'mail' not in session:
        abort(404)

    db = get_db()
    user = db.execute('SELECT * FROM user WHERE email = ?',
                      (session['mail'],)).fetchone()
    if user is None:
        abort(404)

    del session['mail']

    # render qrcode
    url = pyqrcode.create('otpauth://totp/:{0}?secret={1}&issuer=Holligans'.format(user['username'], user['otpSecret']))
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@bp.route('/token_endpoint')
def token_endpoint():
    rt = request.args.get('rt')
    at = request.args.get('at')
 
    #Caso ricezione ar e rt
    if at != 'None' and rt != 'None':

        rt = base64.urlsafe_b64decode(rt)
        at = base64.urlsafe_b64decode(at)

        #Decifro il payload 
        with open('/home/andrea/github/progettoSoa/oauth/cert/private_key.pem', 'rb') as key_file:
	        private_key = serialization.load_pem_private_key(
	            key_file.read(),
	            password = None,
	            backend = default_backend()
                )
        rt = literal_eval(rt.decode("utf-8"))
        at = literal_eval(at.decode("utf-8"))
        rt['payload'] = private_key.decrypt(
	        rt['payload'],
	        padding.OAEP(
	    	    	mgf = padding.MGF1(algorithm=hashes.SHA1()),
	    		    algorithm = hashes.SHA1(),
	    		    label = None
	    	)
	    )

        at['payload'] = private_key.decrypt(
	        at['payload'],
	        padding.OAEP(
	    	    	mgf = padding.MGF1(algorithm=hashes.SHA1()),
	    		    algorithm = hashes.SHA1(),
	    		    label = None
	    	)
	    )

        rt_token_JWT_unencoded = '{}.{}.{}'.format(rt['header'],rt['payload'].decode("utf-8"),rt['sign'])
        at_token_JWT_unencoded = '{}.{}.{}'.format(at['header'],at['payload'].decode("utf-8"),at['sign'])

        #Verifico la firma
        with open('/home/andrea/github/progettoSoa/oauth/cert/public_sign.pub', 'rb') as public_key:
            rt_token = jwt.decode(rt_token_JWT_unencoded, public_key.read(), audience='https://localhost:8100/',algorithms=["RS256"])
        with open('/home/andrea/github/progettoSoa/oauth/cert/public_sign.pub', 'rb') as public_key:
            at_token = jwt.decode(at_token_JWT_unencoded, public_key.read(), audience='https://localhost:8100/', algorithms=["RS256"])

        if(controllo_token(rt_token, at_token)):
            resp = make_response(redirect(url_for('auth.token_operation')))       
            resp.set_cookie('refresh_token', str(rt_token), expires=rt_token['exp'])    
            resp.set_cookie('access_token', str(at_token), expires=at_token['exp'])
            return resp
        else:
            return 'Token non validi'
    # Caso ricezione solo at
    else:
        at = base64.urlsafe_b64decode(at)
        #Decifro il payload 
        with open('/home/andrea/github/progettoSoa/oauth/cert/private_key.pem', 'rb') as key_file:
	        private_key = serialization.load_pem_private_key(
	            key_file.read(),
	            password = None,
	            backend = default_backend()
                )
        at = literal_eval(at.decode("utf-8"))
        at['payload'] = private_key.decrypt(
	        at['payload'],
	        padding.OAEP(
	    	    	mgf = padding.MGF1(algorithm=hashes.SHA1()),
	    		    algorithm = hashes.SHA1(),
	    		    label = None
	    	)
	    )
        at_token_JWT_unencoded = '{}.{}.{}'.format(at['header'],at['payload'].decode("utf-8"),at['sign'])
        with open('/home/andrea/github/progettoSoa/oauth/cert/public_sign.pub', 'rb') as public_key:
            at_token = jwt.decode(at_token_JWT_unencoded, public_key.read(), audience='https://localhost:8100/', algorithms=["RS256"])

        if(controllo_token(at_token)):
            resp = make_response(redirect(url_for('auth.token_operation')))       
            resp.set_cookie('access_token', str(at_token), expires=at_token['exp'])
            return resp
        else:
            return 'Token non validi'

@bp.route('/token_operation')
def token_operation():
    at = literal_eval(request.cookies.get('access_token'))

    db = get_db()
    user = db.execute('SELECT * FROM user WHERE email = ?',
                      (at['sub'],)).fetchone()

    if user is None:
        otpSecret = base64.b32encode(os.urandom(10)).decode('utf-8')
        db.execute('INSERT INTO user (email, username, password, otpSecret, token_required) VALUES (?, ?, ?, ?,?)',
                   (at['sub'], at['sub'].split('@')[0], at['psw'], otpSecret, 1)
                   )
        db.commit()

        session['mail'] = at['sub']
        return redirect(url_for('auth.two_factor_setup'))
    else:
        if user['token_required'] == 0:
            error = 'Utente già presente'
            flash(error)
            return redirect(url_for('auth.login'))
        else:
            if request.cookies.get('refresh_token') == None:
                db = get_db()
                error = None
                user = db.execute('SELECT * FROM user WHERE email = ?',
                                  (at['sub'],)).fetchone()

                if user is None:
                    error = 'Mail errata nel token'
                elif user['password'] != at['psw']:
                    error = 'Pasword errata nel token {}\n{}'.format(user['password'], at['psw'])
                if error is None:
                    # pulisce le sessioni precednti
                    session.clear()
                    # crea la sessione corrente
                    session['mail'] = at['sub']
                    return redirect(url_for('auth.otp_page'))
            else:
                rt = literal_eval(request.cookies.get('refresh_token'))
                user = db.execute('SELECT * FROM user WHERE email = ?',
                                  (rt['sub'],)).fetchone()
                session['user_id'] = user['id']     
                return redirect(url_for('site.index'))
        
        session.clear()
        flash(error)
        return redirect(url_for('site.index'))
    #return 'Qualcosa è andato storto'

@bp.route('/login/oauth')
def login_oauth():
        
    return redirect('https://127.0.0.1:9001/auth/login?redirect_uri=https://127.0.0.1:9001/rURI&scope=hooligans&response_type=code')

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash('Registrazione obbligatoria')
            return redirect(url_for('auth.login'))

        db = get_db()
        user_id = session.get('user_id')
        user = db.execute('SELECT * FROM user WHERE id = ?',
                      (user_id,)).fetchone()

        if request.cookies.get('refresh_token') == None and user['token_required'] == 1:
            flash('Token Scaduto')
            session.clear()
            return redirect(url_for('auth.login'))
        else:
            if request.cookies.get('access_token') == None and user['token_required'] == 1:
                cs = request.cookies.get('clientSecret')
                ci = request.cookies.get('clientId')
                rt = literal_eval(request.cookies.get('refresh_token'))
                return redirect('https://127.0.0.1:9001/auth/generateToken?clientSecret={}&clientId={}&grant_type=refresh_token&mail={}'.format(cs,ci,rt['sub']))
        return view(**kwargs)

    return wrapped_view