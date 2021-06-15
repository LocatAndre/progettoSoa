from os import error
from flask  import  Blueprint, url_for, g, redirect, session, render_template, flash, request
from .auth import login_required

from application.footballDataAPI.footballData import(
    get_competitions,
    get_matchday,
    get_current_league_matchday,
    get_team_info,
    add_to_favourites,
    check_alreadyfav,
    remove_to_favourites,
    get_favourite_team,
    get_user,
    delete_User
)

bp = Blueprint('site', __name__)

@bp.route('/')
def index():
    return render_template('/site/index.html')

@bp.route('/competitions')
@login_required
def competitions():
    data = get_competitions()
    return render_template('/site/competition.html', data = data)

@bp.route('/result/<competition>/<matchday>')
@login_required
def selected_league(competition,matchday):
    data = get_matchday(competition, matchday)
    cmd = get_current_league_matchday(competition)
    
    return render_template('/site/result.html', data = data, cmd = cmd, md = int(matchday), competition = competition)

@bp.route('/team/<competition>/<team>')
@login_required
def team(competition, team):
    user_id = session.get('user_id')
    data = get_team_info(team)
    check_fav = check_alreadyfav(user_id, team)
    cmd = get_current_league_matchday(int(competition))

    return render_template('/site/team.html', team = data, check_fav = check_fav, competition = int(competition), cmd = cmd)

@bp.route('/team/<competition>/<team>/addFavourites')
@login_required
def addfavourites(competition, team):
    user_id = session.get('user_id')
    add_to_favourites(user_id, team)

    data = get_team_info(team)
    return redirect(url_for('site.team', competition=competition, team=team))

@bp.route('/team/<competition>/<team>/removeFavourites')
@login_required
def removeFavourites(competition, team):
    user_id = session.get('user_id')
    remove_to_favourites(user_id, team)

    data = get_team_info(team)
    return redirect(url_for('site.team', competition=competition, team=team))

@bp.route('/team/favourites')
@login_required
def favouriteTeam():
    user_id = session.get('user_id')
    data = get_favourite_team(user_id)
    return render_template('/site/favourite.html', team = data)

@bp.route('/user/updateUser', methods=['POST'])
@login_required
def updateUser():
    username = request.form['username']
    password1 = request.form['password1']
    oldPassword = request.form['oldPassword']
    password2 = request.form['password2']
    email = request.form['email']

    user_id = session.get('user_id')
    user = get_user(user_id)

    from application.footballDataAPI.footballData import get_db
    from werkzeug.security import check_password_hash, generate_password_hash
    if username != user['username']:
        db = get_db()
        db.execute('UPDATE user SET username=? WHERE id=?', (username, user_id))
        db.commit()
    if user['token_required'] == 0:
        if password1 != '' and password2 != '':
            if password1 == password2:
                if len(password1) < 8:
                    flash('Password troppo fragile')
                    return  redirect(url_for('site.userInfo'))
                elif not check_password_hash(user['password'], oldPassword):
                    flash('Vecchia password errata')
                    return  redirect(url_for('site.userInfo'))
                else:
                    db = get_db()
                    db.execute('UPDATE user SET password=? WHERE id=?', (generate_password_hash(password1), user_id))
                    db.commit()
            else:
                flash('Le 2 password non coincidono')
                return  redirect(url_for('site.userInfo'))
        if email != user['email']:
            db = get_db()
            if db.execute('SELECT id FROM user WHERE email = ?', (email,)).fetchone() is not None:
                flash('Mail già presente')
                return  redirect(url_for('site.userInfo'))
            else:
                db.execute('UPDATE user SET email=? WHERE id=?', (email, user_id))
                db.commit()
        else:
            flash('Non puoi cambiare queste credenziali, Login da server Oauth')
            return redirect(url_for('site.userInfo'))

    return redirect(url_for('site.userInfo'))

@bp.route('/user')
@login_required
def userInfo():
    user = get_user(session.get('user_id'))
    return render_template('/site/user_info.html', user = user)

@bp.route('/user/delete')
@login_required
def deleteUser():
    user_id = session.get('user_id')
    delete_User(user_id)
    session.clear()
    return redirect(url_for('site.index'))