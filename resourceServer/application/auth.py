import functools
import onetimepass
import pyqrcode
from io import BytesIO
import os
import base64

from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
    abort
)

from werkzeug.security import (
    check_password_hash,
    generate_password_hash
)

from .db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/login')
def login():
    return render_template('site/login.html')


@bp.route('/login/checkuser', methods=['POST'])
def checkuser():
    email = request.form.get('email')
    password = request.form.get('password')
    otp = request.form.get('otp')

    db = get_db()
    error = None
    user = db.execute('SELECT * FROM user WHERE email = ?',
                      (email,)).fetchone()

    if user is None:
        error = 'Mail non presente'
    elif not check_password_hash(user['password'], password):
        error = 'Pasword errata'
    elif not onetimepass.valid_totp(otp, user['otpSecret']):
        error = 'OTP errato' + otp

    if error is None:
        # pulisce le sessioni precednti
        session.clear()
        # crea un cookie di sessione per la sessione corrente
        session['user_id'] = user['id']
        return redirect(url_for('site.index'))

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

    return render_template('site/2fa.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@bp.route('/controlloToken', methods=['POST', 'GET'])
def controlloToken():
    print('Eccomi')
    return 'Eccomi'

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
    import url64

    rt = request.args.get('rt')
    at = request.args.get('at')

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    
    #Decifro il payload 
    with open('/home/andrea/github/progettoSoa/oauth/cert/private_key.pem', 'rb') as key_file:
	    private_key = serialization.load_pem_private_key(
	        key_file.read(),
	        password = None,
	        backend = default_backend()
            )
    from ast import literal_eval
    rt = literal_eval(rt)
    at = literal_eval(at)

    rt['payload'] = private_key.decrypt(
	    base64.urlsafe_b64decode(rt['payload']),
	    padding.OAEP(
		    	mgf = padding.MGF1(algorithm=hashes.SHA1()),
			    algorithm = hashes.SHA1(),
			    label = None
		)
	)

    at['payload'] = private_key.decrypt(
	    base64.urlsafe_b64decode(at['payload']),
	    padding.OAEP(
		    	mgf = padding.MGF1(algorithm=hashes.SHA1()),
			    algorithm = hashes.SHA1(),
			    label = None
		)
	)

    rt_token_JWT_unencoded = '{}.{}.{}'.format(rt['header'],rt['payload'].decode("utf-8"),rt['sign'])
    at_token_JWT_unencoded = '{}.{}.{}'.format(at['header'],at['payload'].decode("utf-8"),at['sign'])

    import jwt
    #Verifico la firma
    with open('/home/andrea/github/progettoSoa/oauth/cert/public_sign.pub', 'rb') as public_key:
        rt_token = jwt.decode(rt_token_JWT_unencoded, public_key.read(), algorithms=["RS256"],options={"verify_signature": False})
    with open('/home/andrea/github/progettoSoa/oauth/cert/public_sign.pub', 'rb') as public_key:
        at_token = jwt.decode(rt_token_JWT_unencoded, public_key.read(), algorithms=["RS256"],options={"verify_signature": False})

    return('Entrambi token decodificati')


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash('Registrazione obbligatoria')
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view
