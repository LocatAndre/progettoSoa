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

import jwt
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from base64 import urlsafe_b64encode

from .db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register')
def register():

    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope')

    return render_template('site/register.html', scope=scope, ru=redirect_uri)

# inseriamo le info del client (clientId e clientSecret) in CLientInformation
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

        # Genero i cookie contententi le informazioni
        # Il client potrà riutilizzarlo per i prossimi login
        resp = make_response(render_template('site/login.html'))
        resp.set_cookie('clientId', clientId, expires=datetime.now(
        ) + timedelta(days=90))
        resp.set_cookie('clientSecret', generate_password_hash(clientSecret),
                        expires=datetime.now() + timedelta(days=90))
        return resp

    flash(error)
    return redirect(url_for('auth.register'))



@bp.route('/login')
def login():

    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope')
    response_type = request.args.get('response_type')

    return render_template('site/login.html', scope=scope, redirect_uri=redirect_uri, response_type=response_type)


@bp.route('/login/checkUser', methods=['POST'])
def checkUser():
    email = request.form.get('email')
    password = request.form.get('password')
    clientId = request.cookies.get('clientId')
    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope')
    response_type = request.args.get('response_type')
    reqId = base64.b32encode(os.urandom(10)).decode('utf-8')

    db = get_db()
    error = None
    user = db.execute('SELECT * FROM UserInformation WHERE username = ?',
                      (email,)).fetchone()

    # qui se non ci sono i cookie (gestiamo navigazione in incognito e cancellazione cookie)
    if clientId == None:
        client_information = db.execute('SELECT clientId, clientSecret FROM ClientInformation WHERE user=?', (email,)).fetchone()

        if user is None:
            error = 'Mail non presente'
        elif not check_password_hash(user['password'], password):
                error = 'Password errata'

        if error is None:
            session['user_id'] = user['username']
            if redirect_uri == None and scope == None and response_type == None:
                # Login utente al solo servizio di autenticazione (senza funzionalità OAuth)
                return redirect(url_for('site.index'))
            else: 
                db.execute('INSERT INTO Request (reqId, clientId, redirectUri, scope, responseType) VALUES(?,?,?,?,?)',
                           (reqId, client_information['clientId'], redirect_uri, scope, response_type)
                           )
                db.commit()
                # Genero i cookie contententi le informazioni del client
                # I client potrà riutilizzare per i prossimi login
                resp = make_response(render_template('site/approve.html', reqId=reqId, scope=scope, redirect_uri=redirect_uri))
                resp.set_cookie('clientId', client_information['clientId'], expires=datetime.now(
                ) + timedelta(days=90))
                resp.set_cookie('clientSecret', generate_password_hash(client_information['clientSecret']),
                                expires=datetime.now() + timedelta(days=90))
                return resp
                #return redirect(url_for('auth.approve', reqId=reqId, scope=scope, redirect_uri=redirect_uri))
    # qua utente non registrato o che credenziali non corrette
    if user is None:
        error = 'Mail non presente'
    elif not check_password_hash(user['password'], password):
        error = 'Mail o password non corretta'

    if error is None:
        # pulisce le sessioni precednti
        # session.clear()
        # crea un cookie di sessione per la sessione corrente
        session['user_id'] = user['username']

        if redirect_uri == None and scope == None and response_type == None:
            # Login utente normale
            return redirect(url_for('site.index'))
        else: #registriamo la richiesta del token (con relativi parametri per successivi controlli)
            db.execute('INSERT INTO Request (reqId, clientId, redirectUri, scope, responseType) VALUES(?,?,?,?,?)',
                       (reqId, clientId, redirect_uri, scope, response_type)
                       )
            db.commit()
            return redirect(url_for('auth.approve', reqId=reqId, scope=scope, redirect_uri=redirect_uri))

    flash(error)
    return redirect(url_for('auth.login'))


@bp.route('/approve')
def approve():

    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope')
    reqId = request.args.get('reqId')

    return render_template('site/approve.html', redirect_uri=redirect_uri, scope=scope, reqId=reqId)

# l'utente deve prestare il proprio consenso alla richiesta di token fatta dal client
@bp.route('/checkApprove', methods=['POST'])
def checkApprove():
    email = session.get('user_id')

    redirect_uri = request.form['redirect_uri']
    scope = request.form['scope']

    reqId = request.form['reqId']

    db = get_db()

    reqId_db = db.execute(
        'SELECT reqId, clientId, scope, responseType, redirectUri FROM Request WHERE reqId=?', (reqId,)).fetchone()
    # qui se non esiste alcuna richiesta di token fatta del client 
    if reqId == None:
        return 'Richiesta sconosciuta'
    else:
        # gestiamo solo responseType uguali a code ('authorization code flow')
        if reqId_db['responseType'] == 'code':
            clientId_cookie = request.cookies.get('clientId')
            if clientId_cookie == reqId_db['clientId']:
                if scope == reqId_db['scope'] and redirect_uri == reqId_db['redirectUri']:
                    # se la richiesta del client è legittima si crea l'authorization code
                    authCode = base64.b32encode(os.urandom(10)).decode('utf-8')
                    db.execute('INSERT INTO Code(authCode, clientId, scope, redirectUri) VALUES(?,?,?,?)',
                               (authCode, reqId_db['clientId'], scope, reqId_db['redirectUri'],))
                    db.commit()
                    # una volta che la richiesta è stata servita viene rimossa da Request
                    # per evitarne il riutilizzo
                    db.execute('DELETE FROM Request WHERE reqId=?', (reqId_db['reqId'],))
                    db.commit()
                    return redirect(url_for('auth.rURI', authCode=authCode, scope=scope, redirect_uri=redirect_uri))
                else:
                    return redirect('auth.logout')
            else:
                return 'reqId sconosciuto'
    return 'errore in fase di approvazione'


# redirect_uri del client 
@bp.route('/rURI')
def rURI():
    authCode = request.args.get('authCode')
    scope = request.args.get('scope')
    redirect_uri = request.args.get('redirect_uri')
    
    # qui se il client sta richiedendo i token per la prima volta
    # o se i token sono entrambi scaduti 
    if authCode != None:
        clientSecret = request.cookies.get('clientSecret')
        clientId = request.cookies.get('clientId')
        grant_type = 'authorization_code'
        
        return redirect(url_for('auth.generate_token', authCode=authCode, clientSecret=clientSecret, clientId=clientId, grant_type=grant_type, scope=scope, redirect_uri=redirect_uri))
    # qui se il client ha ancora il refresh_token e deve richiedere un nuovo acccess_token
    else:
        rt = request.args.get('rt')
        at = request.args.get('at')
        # qui inviamo i token al token_endpoint del resource server
        return redirect('https://127.0.0.1:8100/auth/token_endpoint?rt={}&at={}'.format(rt,at))



@bp.route('/generateToken')
def generate_token():
    authCode = request.args.get('authCode')
    clientSecret = request.args.get('clientSecret')
    clientId = request.args.get('clientId')
    grant_type = request.args.get('grant_type')
    mail = request.args.get('mail')
    scope = request.args.get('scope')
    redirect_uri = request.args.get('redirect_uri')

    db = get_db()
    check_information = db.execute(
        'SELECT authCode, clientSecret, scope, redirectUri FROM ClientInformation INNER JOIN Code ON Code.clientId = ClientInformation.clientId WHERE clientInformation.clientId=?', (clientId,)).fetchone()

    if mail is not None:
        u_data = db.execute('SELECT username,password FROM UserInformation WHERE username=?', (mail,)).fetchone()
        user = u_data['username']
        psw = u_data['password']
    else:
        psw = db.execute('SELECT password FROM UserInformation WHERE username=?', (session.get('user_id'),)).fetchone()['password']
    # qui generiamo i token quando vengono richiesti per la prima volta (o sono scaduti)
    # il client deve presentare l'authorization code
    if grant_type == 'authorization_code':
        # qui controlliamo che l'authCode sia legittimo e che sia stato sottoposto da il client
        # oer il quale è stato generato (confrontiamo gli hash dei clientSecret)
        if authCode == check_information['authCode'] and check_password_hash(clientSecret, check_information['clientSecret']) and scope == check_information['scope'] and redirect_uri == check_information['redirectUri']:
            # puliamo la tabella del refresh_token perché, se scaduto, non è più utilizzabile ma rimane
            # in memoria (non permettendo di inserire un'altra tupla per lo stesso clientSecret)
            db.execute('DELETE FROM RefreshToken WHERE clientSecret=?', (clientSecret,))
            db.commit()            

            date = datetime.now()
            date_exp_at = date + timedelta(minutes=30)
            date_exp_rt = date + timedelta(minutes=120)

            # creazione token (access e refresh, stesse informazioni ma scadenza diversa)
            payload_AT = {
              'iss':    'https://localhost:9001/', # chi ha emesso il token
              'sub':    session.get('user_id'), # utente per il quale è stato emesso il token
              'psw':    psw, # password utente 
              'aud':    'https://localhost:8100/', # destinatario del token 
              'iat':    date.timestamp(), # momento di emissione token (in secondi trascorsi dal 1 gennaio 1970)
              'exp':    date_exp_at.timestamp(), # scadenza token
              'jti':    base64.b32encode(os.urandom(10)).decode('utf-8') # identificativo del token
            }

            payload_RT = {
                'iss':  'https://localhost:9001/',
                'sub':  session.get('user_id'),
                'psw':  psw,
                'aud':  'https://localhost:8100/',
                'iat':  date.timestamp(),
                'exp':  date_exp_rt.timestamp(),
                'jti':  base64.b32encode(os.urandom(10)).decode('utf-8')
            }
            # Firma dei token con RSA (firmiamo con k_priv server OAuth)
            with open('/home/andrea/github/progettoSoa/oauth/cert/private_sign.pem', 'rb') as private_key:
                token_jwt_AT = jwt.encode(payload_AT, private_key.read(), algorithm="RS256")
            with open('/home/andrea/github/progettoSoa/oauth/cert/private_sign.pem', 'rb') as private_key:
                token_jwt_RT = jwt.encode(payload_RT, private_key.read(), algorithm="RS256")

            # Leggo la chiave privata da cui ricaviamo k_pubb per la cifratura
            with open('/home/andrea/github/progettoSoa/oauth/cert/private_key.pem', 'rb') as key_file:
		            private_key = serialization.load_pem_private_key(
			            key_file.read(),
			            password = None,
			            backend = default_backend()
			            )
            public_key = private_key.public_key()

            # Divido il token per ogni . (header, payload e sign)
            splitted_at = token_jwt_AT.split('.')
            #firmiamo il token con la k_pubb del resource server
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
                'payload':  splitted_at[1],
                'sign':     splitted_at[2]
            }

            final_token_rt = {
                'header':   splitted_rt[0],
                'payload':  splitted_rt[1],
                'sign':     splitted_rt[2]
            }

            db.execute('INSERT INTO RefreshToken(clientSecret, refreshToken) VALUES (?,?)', (clientSecret, token_jwt_RT))
            db.commit()
            # cancelliamo l'authCode già utilizzato per evitare CSRF
            print('auth code da cancellare: ', authCode)
            print('clientId: ', clientId)
            db.execute('DELETE FROM Code WHERE authCode=? AND clientId=?', (authCode, clientId))
            db.commit()

            return redirect(url_for('auth.rURI', rt = base64.urlsafe_b64encode(bytes(str(final_token_rt),'utf-8')), at = base64.urlsafe_b64encode(bytes(str(final_token_at),'utf-8'))))
        else:
            return 'Gli authCode non coincidono'
    # qui se refresh_token è ancora valido
    # generiamo un altro access_token
    elif grant_type == 'refresh_token':
            date = datetime.now()
            date_exp_at = date + timedelta(minutes=30)
            date_exp_rt = date + timedelta(minutes=120)

            payload_AT = {
              'iss':    'https://localhost:9001/',
              'sub':    user,
              'psw':    psw,
              'aud':    'https://localhost:8100/',
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
                'payload':  splitted_at[1],
                'sign':     splitted_at[2]
            }
            return redirect(url_for('auth.rURI', rt = None, at = base64.urlsafe_b64encode(bytes(str(final_token_at), 'utf-8'))))
    else:
        return 'Token non supportato'
        


@bp.before_app_request # facciamo questo controllo prima di ogni richiesta
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



def login_required(view):
    @functools.wraps(view) 
    def wrapped_view(**kwargs):
        if g.user is None:
            flash('Registrazione obbligatoria')
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view
