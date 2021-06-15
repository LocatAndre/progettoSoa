from flask import  Flask

def init_app():
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object('config.DevConfig')

    #from application.footballDataAPI.footballData import get_all_current_league_matchday
    #with app.app_context():
    #    get_all_current_league_matchday()

    from . import db
    db.init_app(app)

    from . import site
    app.register_blueprint(site.bp)

    from . import auth
    app.register_blueprint(auth.bp)

    return app