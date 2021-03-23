import http.client
import sqlite3
import json
from flask import current_app, g

site = 'api.football-data.org'
teams = '/v2/teams/'
competitions = '/v2/competitions'
matches = '/v2/matches'


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        # row torna dati come dizionari
        g.db.row_factory = sqlite3.Row
    return g.db


def get_team_info_from_api(id):

    api_key = current_app.config['API_KEY']
    connection = http.client.HTTPConnection(site)
    headers = {'X-Auth-Token': api_key}

    connection.request('GET', competitions+'/'+str(id)+'/teams', None, headers)
    response = json.loads(connection.getresponse().read().decode())

    for team in response['teams']:
        if team['crestUrl'] == None:
            team['crestUrl'] = '../static/image/error.svg'
        db = get_db()
        db.execute('''INSERT OR IGNORE INTO team (id, name, shortname, tla, logo, venue, founded, clubColors, website) VALUES (?,?,?,?,?,?,?,?,?)''',
                   (team['id'], team['name'], team['shortName'], team['tla'],
                    team['crestUrl'], team['venue'], team['founded'], team['clubColors'], team['website'])
                   )
        db.commit()


def get_league_info_from_api():
    api_key = current_app.config['API_KEY']
    connection = http.client.HTTPConnection(site)
    headers = {'X-Auth-Token': api_key}
    connection.request('GET', competitions+'?plan=TIER_ONE', None, headers)
    response = json.loads(connection.getresponse().read().decode())

    listLeague = []
    for c in response['competitions']:
        if c['area']['countryCode'] == 'BRA':
            c['area']['ensignUrl'] = '../static/image/flag/brazil.svg'
        elif c['area']['countryCode'] == 'FRA':
            c['area']['ensignUrl'] = '../static/image/flag/france.svg'
        elif c['area']['countryCode'] == 'ITA':
            c['area']['ensignUrl'] = '../static/image/flag/italy.svg'
        elif c['area']['countryCode'] == 'ENG':
            c['area']['ensignUrl'] = '../static/image/flag/england.svg'
        elif c['area']['countryCode'] == 'DEU':
            c['area']['ensignUrl'] = '../static/image/flag/germany.svg'
        elif c['area']['countryCode'] == 'PRT':
            c['area']['ensignUrl'] = '../static/image/flag/portugal.svg'
        elif c['area']['countryCode'] == 'INT':
            c['area']['ensignUrl'] = '../static/image/flag/worldwide.svg'
        elif c['area']['countryCode'] == 'NLD':
            c['area']['ensignUrl'] = '../static/image/flag/netherlands.svg'
        elif c['area']['countryCode'] == 'ESP':
            c['area']['ensignUrl'] = '../static/image/flag/spain.svg'
        elif c['area']['countryCode'] == 'EUR':
            c['area']['ensignUrl'] = '../static/image/flag/european-union.svg'

        db = get_db()
        db.execute('INSERT INTO competition(id, name, nation, startComp, endComp) VALUES (?,?,?,?,?)',
                   (c['id'], short_team_name(c['name']), c['area']['ensignUrl'],
                    c['currentSeason']['startDate'], c['currentSeason']['endDate'])
                   )
        db.commit()

    return listLeague


def live_match_from_api():
    api_key = current_app.config['API_KEY']
    connection = http.client.HTTPConnection(site)
    headers = {'X-Auth-Token': api_key}

    connection.request('GET', matches+'?status=LIVE', None, headers)
    response = json.loads(connection.getresponse().read().decode())

    return response['matches']


def get_current_league_matchday_from_api():
    api_key = current_app.config['API_KEY']
    connection = http.client.HTTPConnection(site)
    headers = {'X-Auth-Token': api_key}

    connection.request('GET', competitions+'?plan=TIER_ONE', None, headers)
    response = json.loads(connection.getresponse().read().decode())

    for c in response['competitions']:
        db = get_db()
        db.execute('UPDATE competition SET currentMatchDay=? WHERE id=?',
                   (c['currentSeason']['currentMatchday'], c['id']))
        db.commit()


def get_current_league_matchday_result_from_api(competition, matchday):

    db = get_db()
    api_key = current_app.config['API_KEY']
    connection = http.client.HTTPConnection(site)
    headers = {'X-Auth-Token': api_key}

    connection.request('GET', competitions+'/'+str(competition) +
                       '/matches?matchday='+str(matchday), None, headers)
    response = json.loads(connection.getresponse().read().decode())
    for m in response['matches']:
        if m['score']['fullTime']['homeTeam'] == None:
            m['score']['fullTime']['homeTeam'] = 0
            m['score']['fullTime']['awayTeam'] = 0

        date = m['utcDate'][0:10]
        time = m['utcDate'][11:16]
        db.execute('''INSERT INTO matches (matchday, competition, homeTeam, awayTeam, homeTeamScore, awayTeamScore, time, dateMatch, status) VALUES (?,?,?,?,?,?,?,?,?)''',
                   (matchday, competition, m['homeTeam']['id'], m['awayTeam']['id'], m['score']['fullTime']['homeTeam'], m['score']['fullTime']['awayTeam'], time, date, m['status']))
        db.commit()


def update_results_from_api(competition, matchday):
    db = get_db()
    api_key = current_app.config['API_KEY']
    connection = http.client.HTTPConnection(site)
    headers = {'X-Auth-Token': api_key}

    connection.request('GET', competitions+'/'+str(competition) +
                       '/matches?matchday='+str(matchday), None, headers)
    response = json.loads(connection.getresponse().read().decode())
    for m in response['matches']:
        if m['score']['fullTime']['homeTeam'] == None:
            m['score']['fullTime']['homeTeam'] = 0
            m['score']['fullTime']['awayTeam'] = 0

        db.execute('''UPDATE matches set homeTeamScore=?, awayTeamScore=?, status=?
                WHERE competition=? and matchday=? and homeTeam=? and awayTeam=?
            ''', (m['score']['fullTime']['homeTeam'], m['score']['fullTime']['awayTeam'], m['status'], competition, matchday, m['homeTeam']['id'], m['awayTeam']['id']))
        db.commit()


def short_team_name(st):
    if 'Lazio' in st:
        return 'Lazio'
    elif 'Crotone' in st:
        return 'Crotone'
    elif 'Atalanta' in st:
        return 'Atalanta'
    elif 'Spezia' in st:
        return 'Spezia'
    elif 'Sassuolo' in st:
        return 'Sassuolo'
    elif 'Hellas' in st:
        return 'Hellas Verona'
    elif 'Benevento' in st:
        return 'Benevento'
    elif 'Fiorentina' in st:
        return 'Fiorentina'
    elif 'Genoa' in st:
        return 'Genoa'
    elif 'Udinese' in st:
        return 'Udinese'
    elif 'Bologna' in st:
        return 'Bologna'
    elif 'Sampdoria' in st:
        return 'Sampdoria'
    elif 'Parma' in st:
        return 'Parma'
    elif 'Roma' in st:
        return 'Roma'
    elif 'Torino' in st:
        return 'Torino'
    elif 'Internazionale Milano' in st:
        return 'Inter'
    elif 'Cagliari' in st:
        return 'Cagliari'
    elif 'Juventus' in st:
        return 'Juventus'
    elif 'Milan' in st:
        return 'Milan'
    elif 'Napoli' in st:
        return 'Napoli'
    elif 'UEFA Champions League' in st:
        return 'Champions League'
    else:
        return st
