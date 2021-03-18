from flask  import  Blueprint, url_for, g, redirect, session, render_template, flash, request
from .footballDataAPI import footballdata
from .auth import login_required

bp = Blueprint('site', __name__)

@bp.route('/')
def index():
    data = footballdata.get_league_info()
    return render_template('index.html', data = data)

@bp.route('/league', methods=['POST'])
@login_required
def selected_league():
    league = request.form['idleague']
    md = request.form['cm']
    data = footballdata.get_current_league_matchday_result(league, md)

    return render_template('result.html', data = data)