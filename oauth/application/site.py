from flask import Blueprint, url_for, g, redirect, session, render_template, flash, request
from .auth import login_required
from .db import get_db
# servono per spezzare il codice
bp = Blueprint('site', __name__)


@bp.route('/')
def index():
    return render_template('/site/index.html')


# futura implementazione
@bp.route('/user/updateUser', methods=['POST'])
@login_required
def updateUser():
    username = request.form['username']
    password1 = request.form['password1']
    oldPassword = request.form['oldPassword']
    password2 = request.form['password2']

    db = get_db()

    user_id = session.get('user_id')
    user = db.execute('SELECT username, password FROM UserInformation WHERE username=?', (user_id,)).fetchone()

    from werkzeug.security import check_password_hash, generate_password_hash
    if password1 != '' and password2 != '':
        if password1 == password2:
            if len(password1) < 8:
                flash('Password troppo fragile')
                return redirect(url_for('site.userInfo'))
            elif not check_password_hash(user['password'], oldPassword):
                flash('Vecchia password errata')
                return redirect(url_for('site.userInfo'))
            else:
                db.execute('UPDATE UserInformation SET password=? WHERE username=?', (generate_password_hash(password1), user_id))
                db.commit()
        else:
            flash('Le 2 password non coincidono')
            return redirect(url_for('site.userInfo'))
    if username != user['username']:
        if db.execute('SELECT username FROM UserInformation WHERE username = ?', (user_id,)).fetchone() is not None:
            flash('Mail già presente')
            return redirect(url_for('site.userInfo'))
        else:
            db.execute('UPDATE UserInformation SET username=? WHERE username=?', (username, user_id))
            db.commit()

    return redirect(url_for('site.userInfo'))

# futura implementazione
@bp.route('/user')
@login_required
def userInfo():
    user_id = session.get('user_id')
    db = get_db()
    user = db.execute('SELECT username, password FROM UserInformation WHERE username=?', (user_id,)).fetchone()

    return render_template('/site/user_info.html', user=user)


# futura implementazione
@bp.route('/user/delete')
@login_required
def deleteUser():
    user_id = session.get('user_id')
    db = get_db()
    db.execute('DELETE FROM UserInformation WHERE username = ?', (user_id,))
    db.commit()
    session.clear()
    return redirect(url_for('site.index'))
