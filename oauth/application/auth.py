import functools
from flask.helpers import make_response
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
    current_app
)
from werkzeug.exceptions import ClientDisconnected

from werkzeug.security import (
    check_password_hash,
    generate_password_hash
)

from .db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/login')
def login():

    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope')
    response_type = request.args.get('response_type')

    return render_template('site/login.html', scope=scope, redirect_uri=redirect_uri, response_type=response_type)


@bp.route('/rURI')
def rURI():
    authCode = request.args.get('authCode')
    
    if authCode != None:
        clientSecret = request.cookies.get('clientSecret')
        clientId = request.cookies.get('clientId')
        grant_type = 'authorization_code'
        
        return redirect(url_for('auth.generate_token', authCode=authCode, clientSecret=clientSecret, clientId=clientId, grant_type=grant_type))
    else:
        rt = request.args.get('rt')
        at = request.args.get('at')
        
        return redirect('http://127.0.0.1:8100/auth/token_endpoint?rt={}&at={}'.format(rt,at))



@bp.route('/generateToken')
def generate_token():
    authCode = request.args.get('authCode')
    clientSecret = request.args.get('clientSecret')
    clientId = request.args.get('clientId')
    grant_type = request.args.get('grant_type')
    mail = request.args.get('mail')

    db = get_db()
    check_information = db.execute(
        'SELECT authCode, clientSecret FROM ClientInformation INNER JOIN Code ON Code.clientId = ClientInformation.clientId WHERE clientInformation.clientId=?', (clientId,)).fetchone()

    if mail is not None:
        u_data = db.execute('SELECT username,password FROM UserInformation WHERE username=?', (mail,)).fetchone()
        user = u_data['username']
        psw = u_data['password']
    else:
        psw = db.execute('SELECT password FROM UserInformation WHERE username=?', (session.get('user_id'),)).fetchone()['password']

    import datetime
    import jwt
    from datetime import datetime, timedelta
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from base64 import urlsafe_b64encode

    if grant_type == 'authorization_code':
        if authCode == check_information['authCode'] and check_password_hash(clientSecret, check_information['clientSecret']):
            
            db.execute('DELETE FROM RefreshToken WHERE clientSecret=?', (clientSecret,))
            db.commit()            

            date = datetime.now()
            date_exp_at = date + timedelta(minutes=30)
            date_exp_rt = date + timedelta(minutes=120)

            payload_AT = {
              'iss':    'http://localhost:9001/',
              'sub':    session.get('user_id'),
              'psw':    psw,
              'aud':    'http://localhost:8100/',
              'iat':    date.timestamp(),
              'exp':    date_exp_at.timestamp(),
              'jti':    base64.b32encode(os.urandom(10)).decode('utf-8')
            }

            payload_RT = {
                'iss':  'http://localhost:9001/',
                'sub':  session.get('user_id'),
                'psw':  psw,
                'aud':  'http://localhost:8100/',
                'iat':  date.timestamp(),
                'exp':  date_exp_rt.timestamp(),
                'jti':  base64.b32encode(os.urandom(10)).decode('utf-8')
            }
            # Firma dei token
            with open('/home/andrea/github/progettoSoa/oauth/cert/private_sign.pem', 'rb') as private_key:
                token_jwt_AT = jwt.encode(payload_AT, private_key.read(), algorithm="RS256")
            with open('/home/andrea/github/progettoSoa/oauth/cert/private_sign.pem', 'rb') as private_key:
                token_jwt_RT = jwt.encode(payload_RT, private_key.read(), algorithm="RS256")

            # Leggo la chiave privata
            with open('/home/andrea/github/progettoSoa/oauth/cert/private_key.pem', 'rb') as key_file:
		            private_key = serialization.load_pem_private_key(
			            key_file.read(),
			            password = None,
			            backend = default_backend()
			            )
            public_key = private_key.public_key()

            # Divido il token per ogni . (header, payload e sign)
            splitted_at = token_jwt_AT.split('.')
            splitted_at[1] = public_key.encrypt(
		            bytes(str(splitted_at[1]), 'utf-8'),
                    padding.OAEP(
			        mgf = padding.MGF1(algorithm=hashes.SHA1()),
			        algorithm = hashes.SHA1(),
			        label = None
			    )
	        ) 
            splitted_rt = token_jwt_RT.split('.')
            splitted_rt[1] = public_key.encrypt(
		            bytes(splitted_rt[1], 'utf-8'),
		            padding.OAEP(
			        mgf = padding.MGF1(algorithm=hashes.SHA1()),
			        algorithm = hashes.SHA1(),
			        label = None
			    )
	        )
            
            final_token_at = {
                'header':   splitted_at[0],
                'payload':  base64.urlsafe_b64encode(splitted_at[1]),
                'sign':     splitted_at[2]
            }

            final_token_rt = {
                'header':   splitted_rt[0],
                'payload':  base64.urlsafe_b64encode(splitted_rt[1]),
                'sign':     splitted_rt[2]
            }

            db.execute('INSERT INTO RefreshToken(clientSecret, refreshToken) VALUES (?,?)', (clientSecret, token_jwt_RT))
            db.commit()
            db.execute('DELETE FROM Code WHERE authCode=? AND clientId=?', (authCode, clientId))
            db.commit()
            return redirect(url_for('auth.rURI', rt = final_token_rt, at = final_token_at))
    
    elif grant_type == 'refresh_token':
            date = datetime.now()
            date_exp_at = date + timedelta(minutes=30)
            date_exp_rt = date + timedelta(minutes=120)

            payload_AT = {
              'iss':    'http://localhost:9001/',
              'sub':    user,
              'psw':    psw,
              'aud':    'http://localhost:8100/',
              'iat':    date.timestamp(),
              'exp':    date_exp_at.timestamp(),
              'jti':    base64.b32encode(os.urandom(10)).decode('utf-8')
            }
            # Firma dei token
            with open('/home/andrea/github/progettoSoa/oauth/cert/private_sign.pem', 'rb') as private_key:
                token_jwt_AT = jwt.encode(payload_AT, private_key.read(), algorithm="RS256")
            # Leggo la chiave privata
            with open('/home/andrea/github/progettoSoa/oauth/cert/private_key.pem', 'rb') as key_file:
		            private_key = serialization.load_pem_private_key(
			            key_file.read(),
			            password = None,
			            backend = default_backend()
			            )
            public_key = private_key.public_key()

            # Divido il token per ogni . (header, payload e sign)
            splitted_at = token_jwt_AT.split('.')
            splitted_at[1] = public_key.encrypt(
		            bytes(str(splitted_at[1]), 'utf-8'),
                    padding.OAEP(
			        mgf = padding.MGF1(algorithm=hashes.SHA1()),
			        algorithm = hashes.SHA1(),
			        label = None
			    )
	        )
            final_token_at = {
                'header':   splitted_at[0],
                'payload':  base64.urlsafe_b64encode(splitted_at[1]),
                'sign':     splitted_at[2]
            }
            return redirect(url_for('auth.rURI', at = final_token_at))
    else:
        return 'Token non supportato'
        

@bp.route('/approve')
def approve():

    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope')
    reqId = request.args.get('reqId')

    return render_template('site/approve.html', redirect_uri=redirect_uri, scope=scope, reqId=reqId)



@bp.route('/checkApprove', methods=['POST'])
def checkApprove():
    email = session.get('user_id')

    redirect_uri = request.form['redirect_uri']
    scope = request.form['scope']

    reqId = request.form['reqId']

    db = get_db()

    reqId_db = db.execute(
        'SELECT reqId, clientId, scope, responseType FROM Request WHERE reqId=?', (reqId,)).fetchone()

    if reqId == None:
        return 'Richiesta sconosciuta'
    else:
        if reqId_db['responseType'] == 'code':
            clientId_cookie = request.cookies.get('clientId')
            if clientId_cookie == reqId_db['clientId']:
                if scope == reqId_db['scope']:
                    authCode = base64.b32encode(os.urandom(10)).decode('utf-8')
                    db.execute('INSERT INTO Code(authCode, clientId, scope) VALUES(?,?,?)',
                               (authCode, reqId_db['clientId'], scope))
                    db.commit()

                    db.execute('DELETE FROM Request WHERE reqId=?', (reqId_db['reqId'],))
                    db.commit()
                    return redirect(url_for('auth.rURI', authCode=authCode))
                else:
                    return redirect('auth.logout')
        else:
            return 'responseType non supportato'


@bp.route('/login/checkuser', methods=['POST'])
def checkuser():
    email = request.form.get('email')
    password = request.form.get('password')

    clientId = request.cookies.get('clientId')

    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope')
    response_type = request.args.get('response_type')

    reqId = base64.b32encode(os.urandom(10)).decode('utf-8')

    print(response_type)

    db = get_db()
    error = None
    user = db.execute('SELECT * FROM UserInformation WHERE username = ?',
                      (email,)).fetchone()

    if user is None:
        error = 'Mail non presente'
    elif not check_password_hash(user['password'], password):
        error = 'Pasword errata'

    if error is None:
        # pulisce le sessioni precednti
        # session.clear()
        # crea un cookie di sessione per la sessione corrente
        session['user_id'] = user['username']

        if redirect_uri == None and scope == None and response_type == None:
            # Login utente normale
            return redirect(url_for('site.index'))
        else:
            db.execute('INSERT INTO Request (reqId, clientId, redirectUri, scope, responseType) VALUES(?,?,?,?,?)',
                       (reqId, clientId, redirect_uri, scope, response_type)
                       )
            db.commit()
            return redirect(url_for('auth.approve', reqId=reqId, scope=scope, redirect_uri=redirect_uri))

    flash(error)
    return redirect(url_for('auth.login'))


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM UserInformation WHERE username = ?', (user_id,)).fetchone()


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('site.index'))


@bp.route('/register/checkregister', methods=['POST'])
def checkregister():
    password1 = request.form['password1']
    password2 = request.form['password2']
    email = request.form['email']

    # Segreto casuale per registrazione client "fisico"
    clientId = base64.b32encode(os.urandom(10)).decode('utf-8')
    clientSecret = base64.b32encode(os.urandom(10)).decode('utf-8')

    db = get_db()
    error = None

    if not password1 or not password2 or not email:
        error = 'Campi mancanti'
    elif db.execute('SELECT username FROM UserInformation WHERE username = ?', (email,)
                    ).fetchone() is not None:
        error = '{} è già iscritto.'.format(email)
    elif password1 != password2:
        error = 'Le 2 password non coincidono'
    elif password1 == password1 and len(password1) < 8:
        error = 'Password troppo fragile'

    if error is None:
        db.execute('INSERT INTO UserInformation(username,password) VALUES(?,?)',
                   (email, generate_password_hash(password1))
                   )
        db.commit()

        db.execute('INSERT INTO ClientInformation(clientId,clientSecret,user) VALUES(?,?,?)',
                   (clientId, clientSecret, email)
                   )
        db.commit()

        import datetime
        # Genero il file contentente le informazioni
        # I client potrà riutilizzare per i prossimi login
        resp = make_response(render_template('site/login.html'))
        resp.set_cookie('clientId', clientId, expires=datetime.datetime.now(
        ) + datetime.timedelta(days=90))
        resp.set_cookie('clientSecret', generate_password_hash(clientSecret),
                        expires=datetime.datetime.now() + datetime.timedelta(days=90))
        return resp

    flash(error)
    return redirect(url_for('auth.register'))


@bp.route('/register')
def register():

    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope')

    return render_template('site/register.html', scope=scope, ru=redirect_uri)


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash('Registrazione obbligatoria')
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view
