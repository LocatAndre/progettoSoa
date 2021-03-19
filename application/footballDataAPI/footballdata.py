import http.client
import json
from flask import current_app, g

site = 'api.football-data.org'
teams = '/v2/teams/'
competitions = '/v2/competitions'
matches = '/v2/matches'


def get_all_team_info(id):

    api_key = current_app.config['API_KEY']
    connection = http.client.HTTPConnection(site)
    headers = {'X-Auth-Token': api_key}

    connection.request('GET', teams+str(id), None, headers)
    response = json.loads(connection.getresponse().read().decode())

    return response


def all_league_team(id):

    api_key = current_app.config['API_KEY']
    connection = http.client.HTTPConnection(site)
    headers = {'X-Auth-Token': api_key}

    connection.request('GET', competitions+'/'+str(id)+'/teams', None, headers)
    response = json.loads(connection.getresponse().read().decode())

    return response['teams']


def live_match():
    api_key = current_app.config['API_KEY']
    connection = http.client.HTTPConnection(site)
    headers = {'X-Auth-Token': api_key}

    connection.request('GET', matches+'?status=LIVE', None, headers)
    response = json.loads(connection.getresponse().read().decode())

    return response['matches']


def get_current_league_matchday(id):
    api_key = current_app.config['API_KEY']
    connection = http.client.HTTPConnection(site)
    headers = {'X-Auth-Token': api_key}

    connection.request('GET', competitions+'?plan=TIER_ONE', None, headers)
    response = json.loads(connection.getresponse().read().decode())
    for c in response['competitions']:
        if int(c['id']) ==  int(id):
            return c['currentSeason']['currentMatchday']

def get_league_info():
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
        league ={
            'name':     short_team_name(c['name']),
            'id':       c['id'],
            'nation':   c['area']['ensignUrl'],
            'matchday': c['currentSeason']['currentMatchday'],
            'start':    c['currentSeason']['startDate'],
            'end':      c['currentSeason']['endDate']
        }
        listLeague.append(league)
    return listLeague


def get_current_league_matchday_result(id, md):

    api_key = current_app.config['API_KEY']
    connection = http.client.HTTPConnection(site)
    headers = {'X-Auth-Token': api_key}

    connection.request('GET', competitions+'/'+str(id) +
                       '/matches?matchday='+str(md), None, headers)
    response = json.loads(connection.getresponse().read().decode())

    matchRes = []

    for m in response['matches']:
        if m['status'] == 'SCHEDULED':
            m['score']['fullTime']['homeTeam'] = 0
            m['score']['fullTime']['awayTeam'] = 0
        match = {
            'date':     m['utcDate'][:10],
            'time':     m['utcDate'][11:16],
            'status':   m['status'],
            'homeTeam': {
                'name':     short_team_name(m['homeTeam']['name']),
                'imgSrc':   'https://crests.football-data.org/' + str(m['homeTeam']['id']) + '.svg'
            },
            'awayTeam': {
                'name':     short_team_name(m['awayTeam']['name']),
                'imgSrc':   'https://crests.football-data.org/' + str(m['awayTeam']['id']) + '.svg'
            },
            'score': {
                'homeTeam': m['score']['fullTime']['homeTeam'],
                'awayTeam': m['score']['fullTime']['awayTeam'],
            },
        }
        matchRes.append(match)

    return matchRes


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
