from flask  import  Blueprint, url_for, g, redirect, session, render_template, flash, request
from .footballDataAPI import footballdata

bp = Blueprint('site', __name__)

@bp.route('/')
def index():
    data = footballdata.get_league_info()
    return render_template('index.html', data = data)