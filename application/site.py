from flask  import  Blueprint, url_for, g, redirect, session, render_template, flash, request
from .footballDataAPI import footballdata
from .auth import login_required

bp = Blueprint('site', __name__)

@bp.route('/')
def index():
    data = footballdata.get_league_info()
    return render_template('index.html', data = data)

@bp.route('/result/<idLeague>/<matchday>')
@login_required
def selected_league(idLeague,matchday):
    league = idLeague
    currentMatchday = footballdata.get_current_league_matchday(league)
    data = footballdata.get_current_league_matchday_result(idLeague, matchday)
    return render_template('result.html', data = data, cmd = currentMatchday, md = matchday, league=idLeague)