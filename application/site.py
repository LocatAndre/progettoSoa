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
    get_favourite_team
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
    
    return render_template('/site/result.html', data = data, cmd = cmd, md = int(matchday), league = competition)

@bp.route('/team/<team>')
@login_required
def team(team):
    user_id = session.get('user_id')
    data = get_team_info(team)
    check_fav = check_alreadyfav(user_id, team)
    return render_template('/site/team.html', team = data, check_fav = check_fav)

@bp.route('/team/<team>/addFavourites')
@login_required
def addfavourites(team):
    user_id = session.get('user_id')
    add_to_favourites(user_id, team)

    data = get_team_info(team)
    return render_template('/site/team.html', team = data, check_fav = True)

@bp.route('/team/<team>/removeFavourites')
@login_required
def removeFavourites(team):
    user_id = session.get('user_id')
    remove_to_favourites(user_id, team)

    data = get_team_info(team)
    return render_template('/site/team.html', team = data, check_fav = False)

@bp.route('/team/favourites')
@login_required
def favouriteTeam():
    user_id = session.get('user_id')
    data = get_favourite_team(user_id)
    return render_template('/site/favourite.html', team = data)
