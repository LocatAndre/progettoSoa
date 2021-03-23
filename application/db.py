import sqlite3
import click

from flask import current_app, g
from flask.cli import with_appcontext
from application.footballDataAPI.extractor import(
    get_league_info_from_api, 
    get_team_info_from_api,
    get_current_league_matchday_result_from_api,
    get_current_league_matchday_from_api

)

def init_db():
    db = get_db()
    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        # row torna dati come dizionari
        g.db.row_factory = sqlite3.Row
    return g.db

@click.command('init-db')
@with_appcontext
def init_db_command():
    init_db()
    click.echo('Creazione database')

@click.command('league-md')
@with_appcontext
def get_current_league_matchday():
    get_current_league_matchday_from_api()
    click.echo('Giornata aggiornata')

@click.command('get-info-team')
@click.argument('team', nargs=1)
@with_appcontext
def add_team(team):
    get_team_info_from_api(team)
    click.echo('Info added')

@click.command('get-league')
@with_appcontext
def add_league():
    get_league_info_from_api()
    click.echo('Leghe aggiunte')

@click.command('get-league-match')
@click.argument('comp', nargs=1)
@click.argument('md', nargs=1)
@with_appcontext
def add_league_matchday(comp, md):
    get_current_league_matchday_result_from_api(comp,md)
    click.echo('Giornata aggiunta')

@click.command('delete-team-table')
def delete_team_tabble():
    db = get_db()
    db.execute('DROP TABLE IF EXISTS team')
    db.commit()

def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
    app.cli.add_command(add_league)
    app.cli.add_command(add_team)
    app.cli.add_command(add_league_matchday)
    app.cli.add_command(get_current_league_matchday)