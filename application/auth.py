import functools

from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for
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

    db = get_db()
    error = None
    user = db.execute('SELECT * FROM user WHERE email = ?',
                      (email,)).fetchone()

    if user is None:
        error = 'Mail non presente'
    elif not check_password_hash(user['password'], password):
        error = 'Pasword errata'

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
        db.execute('INSERT INTO user (email, username, password) VALUES (?, ?, ?)',
                   (email, username, generate_password_hash(password1))
                   )
        db.commit()
        return redirect(url_for('auth.login'))

    flash(error)
    return redirect(url_for('auth.register'))


@bp.route('/register')
def register():
    return render_template('site/register.html')


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash('Registrazione obbligatoria')
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view
