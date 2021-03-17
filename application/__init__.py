from flask import  Flask

def init_app():
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object('config.DevConfig')

    from . import db
    db.init_app(app)

    from . import site
    app.register_blueprint(site.bp)

    from . import auth
    app.register_blueprint(auth.bp)

    return app



