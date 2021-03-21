from flask  import  Blueprint, url_for, g, redirect, session, render_template, flash, request
from .auth import login_required

from application.footballDataAPI.footballData import(
    get_competitions,
    get_matchday,
    get_current_league_matchday
)

bp = Blueprint('site', __name__)

@bp.route('/')
def index():
    data = get_competitions()
    return render_template('index.html', data = data)

@bp.route('/result/<competition>/<matchday>')
@login_required
def selected_league(competition,matchday):
    data = get_matchday(competition, matchday)
    cmd = get_current_league_matchday(competition)
    
    return render_template('result.html', data = data, cmd = cmd, md = int(matchday), league = competition)