# import packages
from datetime import timedelta
from flask import Flask, flash, jsonify, redirect, request, render_template, session, url_for
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, UserMixin, current_user, login_user, login_required, logout_user
from flask_sqlalchemy import SQLAlchemy
from urllib.parse import urlparse, urljoin
from werkzeug.security import generate_password_hash, check_password_hash
# import user defined classes
from forms import LoginForm, SignupForm, ChangePassword

# app initialization
app = Flask(__name__)
Bootstrap(app)
db = SQLAlchemy(app)

# app configuration
app.config.update(
    SQLALCHEMY_DATABASE_URI='sqlite:////home/rodox/git/restaurant-menu-api/restaurant_menu.db',
    SECRET_KEY='SEGREDO',
    USE_SESSION_FOR_NEXT=True,
    REMEMBER_COOKIE_DURATION=timedelta(hours=4)
)

# login manager configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'We don\'t recognize you, please login to access the page.'

# user database class
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=False)

# restaurant database class
class Restaurant(db.Model):
    __tablename__ = 'restaurant'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    address = db.Column(db.String(500))
    phone = db.Column(db.String(20))

# menu item database class
class MenuItem(db.Model):
    __tablename__ = 'item'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(250))
    price = db.Column(db.String(8))
    course = db.Column(db.String(250))
    restaurant_id = db.Column(db.Integer, db.ForeignKey('restaurant.id'))
    
    # relationship with restaurant table
    restaurant = db.relationship(Restaurant)

# url verification function
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# login loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# route for home page
@app.route('/')
def home():
    return render_template('home.html')

# route for login page
@app.route('/login/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    else:
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                if check_password_hash(user.password, form.password.data):
                    login_user(user, remember=form.remember.data)
                    if 'next' in session:
                        next_url = session['next']
                        session['next'] = None
                        if is_safe_url(next_url) and next_url is not None:
                            return redirect(next_url)
                    flash('Welcome back, %s!' % user.name)
                    return redirect(url_for('home'))
            flash('Invalid user or password.')
        return render_template('login.html', form=form)

# route to logout page, redirect to login page
@app.route('/logout/')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# route to signup page
@app.route('/signup/', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    else:
        form = SignupForm()
        if form.validate_on_submit():
            # generate a password hash 80 characters long
            password_hash = generate_password_hash(form.password.data, method='sha256')
            user = User(username=form.username.data,
                        email=form.email.data,
                        password=password_hash,
                        name=form.name.data)
            db.session.add(user)
            db.session.commit()
            flash('User "%s" has been created.' % form.username.data)
            return redirect(url_for('login'))
        return render_template('signup.html', form=form)

# route to profile page
@app.route('/profile/')
@login_required
def profile():
    user = User.query.filter_by(username=current_user.username).first()
    return render_template('profile.html', user=user)

@app.route('/changepasswd', methods=['GET', 'POST'])
@login_required
def changePassword():
    form = ChangePassword()
    if form.validate_on_submit():
        user = User.query.filter_by(username=current_user.username).first()
        print(check_password_hash(user.password, form.old.data))
        if check_password_hash(user.password, form.old.data):
            user.password = generate_password_hash(form.new.data, method='sha256')
            db.session.add(user)
            db.session.commit()
            flash('Password successfully changed.')
            return redirect(url_for('logout'))
        flash('Invalid password.')
    return render_template('change_password.html', form=form)

#@app.route('/restaurants/<int:restaurant_id>/JSON/',
#           methods=['GET'])
#def restaurantMenuJSON(restaurant_id):
#    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id).all()
#    return jsonify(MenuItems=[item.serialize for item in items])

if __name__ == '__main__':
    app.run(host='localhost', port=8000, debug=True)