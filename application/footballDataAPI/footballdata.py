import http.client
import json
from flask import current_app, g

site = 'api.football-data.org'
teams = '/v2/teams/'
competitions = '/v2/competitions/'
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

    connection.request('GET', competitions+str(id)+'/teams', None, headers)
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

    connection.request('GET', competitions+str(id), None, headers)
    response = json.loads(connection.getresponse().read().decode())

    return response['currentSeason']['currentMatchday']


def get_current_league_matchday_result(id, md):

    api_key = current_app.config['API_KEY']
    connection = http.client.HTTPConnection(site)
    headers = {'X-Auth-Token': api_key}

    connection.request('GET', competitions+str(id) +
                       '/matches?matchday='+str(md), None, headers)
    response = json.loads(connection.getresponse().read().decode())

    matchRes = []

    for m in response['matches']:
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
            'referees': {
                'main':     m['referees'][0]['name'],
                'var':      m['referees'][4]['name'],
            }
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
    else:
        return st
