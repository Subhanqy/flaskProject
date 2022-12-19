# IMPORTS
import copy
import logging
import os
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, render_template, request, abort
from flask_login import LoginManager, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman

load_dotenv()


# LOGGING
class SecurityFilter(logging.Filter):
    def filter(self, record):
        return "SECURITY" in record.getMessage()


# CONFIG
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lottery.db'
app.config['SQLALCHEMY_ECHO'] = os.getenv('SQLALCHEMY_ECHO')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY')


## FUNCTIONS
def requires_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.roles not in roles:
                logging.warning('SECURITY - Unauthorised access attempt [%s, %s, %s, %s]',
                                current_user.id,
                                current_user.email,
                                current_user.role,
                                request.remote_addr)
                # Redirect the user to an unauthorised notice!
                return abort(403, 'Forbidden')
            return f(*args, **kwargs)

        return wrapped

    return wrapper


# decrypt original draws
def decrypt_draws(draws):
    # creates a list of copied draw objects which are independent of database.
    draws_copies = list(map(lambda x: copy.deepcopy(x), draws))
    # empty list for decrypted copied draw objects
    decrypted_draws = []

    # decrypt each copied draw object and add it to decrypted_draws array.
    for d in draws_copies:
        d.view_draw(current_user.draw_key)
        decrypted_draws.append(d)

    return decrypted_draws


# initialise database
db = SQLAlchemy(app)

# Security Headers
csp = {
    'default-src': ['\'self\'', 'https://cdnjs.cloudflare.com/ajax/libs/bulma/0.7.2/css/bulma.min.css'],
    'frame-src': ['\'self\'', 'https://www.google.com/recaptcha/', 'https://recaptcha.google.com/recaptcha/'],
    'script-src': ['\'self\'', '\'unsafe-inline\'', 'https://www.google.com/recaptcha/',
                   'https://www.gstatic.com/recaptcha/']
}
talisman = Talisman(app, content_security_policy=csp)

# BLUEPRINTS
# import blueprints
from users.views import users_blueprint
from admin.views import admin_blueprint
from lottery.views import lottery_blueprint

# register blueprints with app
app.register_blueprint(users_blueprint)
app.register_blueprint(admin_blueprint)
app.register_blueprint(lottery_blueprint)

from models import User

# instance of Login manager
login_manager = LoginManager()
login_manager.login_view = 'users.login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.errorhandler(400)
def handle_bad_request(error):
    return render_template('errors/400.html'), 400


@app.errorhandler(403)
def handle_forbidden(error):
    return render_template('errors/403.html'), 403


@app.errorhandler(404)
def handle_not_found(error):
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def handle_server_error(error):
    return render_template('errors/500.html'), 500


@app.errorhandler(503)
def handle_service_unavailable(error):
    return render_template('errors/503.html'), 503


# HOME PAGE VIEW
@app.route('/')
def index():
    return render_template('main/index.html')


if __name__ == "__main__":
    app.run(ssl_context='adhoc')
