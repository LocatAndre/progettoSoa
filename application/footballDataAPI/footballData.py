import sqlite3
from flask import current_app, g

from application.footballDataAPI.extractor import(
    get_current_league_matchday_result_from_api,
    get_current_league_matchday_from_api,
    update_results_from_api
)


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        # row torna dati come dizionari
        g.db.row_factory = sqlite3.Row
    return g.db


def get_competitions():
    ## Implementare una volta al giorno
    #get_current_league_matchday_from_api()
    db = get_db()
    return db.execute('select * from competition').fetchall()


def get_matchday(competition, matchday):
    db = get_db()

    currentMatchDay = db.execute('SELECT currentMatchDay from competition WHERE id=?', (competition,)).fetchone()

    if matchday == currentMatchDay:
        update_results_from_api()

    matches = db.execute('''SELECT * FROM matches
        WHERE matchday=? and competition=?''',
                         (matchday, competition,)
                         ).fetchone()
    if matches == None:
        get_current_league_matchday_result_from_api(competition, matchday)
        matches = db.execute('''SELECT matchday, homeTeamScore, awayTeamScore, time, dateMatch, t1.tla as hname, t2.tla as aname, t1.logo as hlogo, t2.logo as alogo FROM matches
        INNER JOIN team AS t1 ON homeTeam = t1.id
        INNER JOIN team AS t2 ON awayTeam = t2.id
        WHERE matchday=? and competition=?''',
                             (matchday, competition,)
                             ).fetchall()
        return matches
    else:
        matches = db.execute('''SELECT matchday, homeTeamScore, awayTeamScore, time, dateMatch, t1.tla as hname, t2.tla as aname, t1.logo as hlogo, t2.logo as alogo FROM matches
        INNER JOIN team AS t1 ON homeTeam = t1.id
        INNER JOIN team AS t2 ON awayTeam = t2.id
        WHERE matchday=? and competition=?''',
                             (matchday, competition,)
                             ).fetchall()
        return matches


def get_current_league_matchday(competition):
    get_current_league_matchday_from_api()
    db = get_db()
    cmd = db.execute(
        'SELECT currentMatchDay FROM competition WHERE id=?', (competition,)).fetchone()[0]
    return cmd
