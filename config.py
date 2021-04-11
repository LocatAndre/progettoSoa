"""Flask configuration."""
from os import environ, path
from dotenv import load_dotenv

basedir = path.abspath(path.dirname(__file__))
load_dotenv(path.join(basedir, '.env'))


class Config:
    """Base config."""
    DATABASE = path.join(path.realpath(path.dirname(__file__)), 'instance/db.sqlite')
    CERTIFICATE_PATH= path.join(path.realpath(path.dirname(__file__)), 'certificate/server.crt')
    SERVER_KEY=path.join(path.realpath(path.dirname(__file__)), 'certificate/server.key')
    SECRET_KEY = environ.get('SECRET_KEY')
    STATIC_FOLDER = 'static'
    TEMPLATES_FOLDER = 'templates'
    API_KEY = environ.get('API_KEY')

class ProdConfig(Config):
    FLASK_ENV = 'production'
    DEBUG = False
    TESTING = False

class DevConfig(Config):
    FLASK_ENV = 'development'
    DEBUG = True
    TESTING = True