import sqlite3
from flask import current_app, g

from application.footballDataAPI.extractor import(
    get_current_league_matchday_result_from_api,
    get_current_league_matchday_from_api,
    update_results_from_api,
    live_match_from_api
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
    db = get_db()
    return db.execute('select * from competition').fetchall()


def get_matchday(competition, matchday):
    db = get_db()

    currentMatchDay = db.execute('SELECT currentMatchDay from competition WHERE id=?', (competition,)).fetchone()['currentMatchDay']

    notFinished = db.execute("SELECT count(id) FROM matches WHERE matchday=? AND status!='FINISHED' and competition=?",(currentMatchDay,competition,)).fetchone()[0]
    if int(matchday) == int(currentMatchDay) and notFinished>0:
        update_results_from_api(competition, matchday)

    matches = db.execute('''SELECT * FROM matches
        WHERE matchday=? and competition=?''',
                         (matchday, competition,)
                         ).fetchone()
    if matches == None:
        get_current_league_matchday_result_from_api(competition, matchday)
        matches = db.execute('''SELECT matchday, matches.competition, homeTeam, awayTeam, homeTeamScore, awayTeamScore, time, dateMatch, t1.tla as hname, t2.tla as aname, t1.logo as hlogo, t2.logo as alogo FROM matches
        INNER JOIN team AS t1 ON homeTeam = t1.id
        INNER JOIN team AS t2 ON awayTeam = t2.id
        WHERE matchday=? and competition=?''',
                             (matchday, competition,)
                             ).fetchall()
        return matches
    else:
        matches = db.execute('''SELECT matchday, matches.competition, homeTeam, awayTeam, homeTeamScore, awayTeamScore, time, dateMatch, t1.tla as hname, t2.tla as aname, t1.logo as hlogo, t2.logo as alogo FROM matches
        INNER JOIN team AS t1 ON homeTeam = t1.id
        INNER JOIN team AS t2 ON awayTeam = t2.id
        WHERE matchday=? and competition=?''',
                             (matchday, competition,)
                             ).fetchall()
        return matches


def get_current_league_matchday(competition):
    db = get_db()
    cmd = db.execute('SELECT currentMatchDay FROM competition WHERE id=?', (competition,)).fetchone()[0]
    return cmd

def get_all_current_league_matchday():
    get_current_league_matchday_from_api()

def get_team_info(team):
    db = get_db()
    return db.execute('SELECT * FROM team WHERE id=?', (team,)).fetchone()

def add_to_favourites(user_id, team):
    db = get_db()

    check = db.execute('SELECT * FROM user_team WHERE team_id=? and user_id=?', (team, user_id,)).fetchone()

    if check == None:
        db.execute('INSERT INTO user_team (user_id, team_id) values (?, ?)', (user_id, team,))
        db.commit()

def check_alreadyfav(user_id, team):
    db = get_db()
    check = db.execute('SELECT * FROM user_team WHERE team_id=? and user_id=?', (team, user_id,)).fetchone()

    if check == None:
        return False
    else:
        return True

def remove_to_favourites(user_id, team):
    db = get_db()

    db.execute('DELETE FROM user_team WHERE user_id=? AND team_id=?', (user_id, team,))
    db.commit()

def get_favourite_team(user_id):
    db = get_db()

    return db.execute('''
        SELECT matchday, homeTeam, awayTeam, homeTeamScore, awayTeamScore, time, dateMatch, t1.tla as hname, t2.tla as aname, t1.logo as hlogo, t2.logo as alogo FROM matches
        INNER JOIN team AS t1 ON homeTeam = t1.id
        INNER JOIN team AS t2 ON awayTeam = t2.id
        INNER JOIN competition ON competition = competition.id
        WHERE matchday=currentMatchDay AND ( 
            homeTeam IN (SELECT team_id FROM user_team WHERE user_id=?) OR 
            awayTeam IN (SELECT team_id FROM user_team WHERE user_id=?)
        ) AND matches.competition != 2001''', (user_id, user_id)
    ).fetchall()

def get_live_result():
    live = live_match_from_api()

    return live

def get_user(user_id):
    db = get_db()
    return db.execute('SELECT * FROM user WHERE id=?', (user_id,)).fetchone()

def delete_User(user_id):
    db = get_db()
    db.execute('DELETE FROM user WHERE id=?', (user_id, ))
    db.commit()