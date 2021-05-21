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
    clientSecret = request.cookies.get('clientSecret')
    clientId = request.cookies.get('clientId')
    grant_type = 'authorization_code'

    return redirect(url_for('auth.generate_token', authCode=authCode, clientSecret=clientSecret, clientId=clientId, grant_type=grant_type))


@bp.route('/generateToken')
def generate_token():
    authCode = request.args.get('authCode')
    clientSecret = request.args.get('clientSecret')
    clientId = request.args.get('clientId')
    grant_type = request.args.get('grant_type')

    db = get_db()

    check_information = db.execute(
        'SELECT authCode, clientSecret FROM ClientInformation INNER JOIN Code ON Code.clientId = ClientInformation.clientId WHERE clientInformation.clientId=?', (clientId,)).fetchone()

    with open(current_app.config['PEM_KEY'], 'r') as private_key:
        if grant_type == 'authorization_code':
            if authCode == check_information['authCode'] and clientSecret == check_information['clientSecret']:
                import jwt
                import datetime
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.backends import default_backend
                payload = {
                  'iss':    'http://localhost:9001/',
                  'sub':    session.get('user_id'),
                  'aud':    'http://localhost:8100/',
                  'iat':    datetime.datetime.now(),
                  'exp':    datetime.datetime.now() + datetime.timedelta(minutes=90),
                  'jti':    base64.b32encode(os.urandom(10)).decode('utf-8')
                }

                token_jwt = jwt.encode(payload, private_key.read(), algorithm="RS256")

                jwt.decode(token_jwt,options={"verify_signature": False})
                return jwt.decode(token_jwt,options={"verify_signature": False})
        elif grant_type == 'refresh_token':
            return 'refresh'
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
        resp.set_cookie('clientSecret', clientSecret,
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
