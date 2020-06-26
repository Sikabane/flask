from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, BooleanField, TextAreaField, validators
from wtforms.validators import InputRequired
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime



app = Flask(__name__)
app.config['SECRET_KEY'] = 'SECRETKEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

Bootstrap(app)
db = SQLAlchemy(app)
Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

groups = db.Table('groups',
    db.Column('user', db.Integer, db.ForeignKey(
        'user.id'), primary_key=True),
    db.Column('group', db.Integer, db.ForeignKey(
        'group.id'), primary_key=True)
    )


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(100))
    location = db.Column(db.String(30))
    created = db.Column(db.DateTime())
    posts = db.relationship (
     'Group', 
     backref = 'user', 
     lazy = True
    )
    groups = db.relationship('Group', secondary=groups, lazy='subquery',
        backref=db.backref('user_group', lazy=True))

class Group(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(255))
    text = db.Column(db.Text)
    publish_date = db.Column(db.DateTime)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'))
    users = db.relationship('User', secondary=groups, lazy='subquery',
        backref=db.backref('group_user', lazy=True))

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    email = StringField('Email', validators=[InputRequired()])
    location = StringField('Location', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired(), 
        validators.EqualTo('confirm', message='Passwords must match')])
    confirm=PasswordField('Repeat Password')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    remember = BooleanField('Remember me')

class GroupForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired()])
    text = TextAreaField('Description', validators=[InputRequired()])

@app.cli.command("dropdb")
def reset_db():
    db.drop_all()

    print("Dropped all tables in databese")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=('GET', 'POST'))
def signup():
    form = SignupForm()

    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data,
            password=generate_password_hash(form.password.data, method='sha256'),
            location=form.location.data, created=datetime.now())
        db.session.add(user)
        db.session.commit()
        login_user(user, remember=True)

        return redirect(url_for('profile'))

    return render_template('signup.html', form=form)

@app.route('/login', methods=('GET', 'POST'))
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('profile'))
                flash('Login Successful')
        flash('Invalid username or password')
        return render_template('login.html', form=form) 
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/group')
@login_required
def group():
    user = db.session.query(User)
    group = db.session.query(Group)
    return render_template('group.html', user=user, group=group)


@app.route('/add_group', methods=('GET', 'POST'))
@login_required
def add_group():
    form = GroupForm()

    if form.validate_on_submit():
        group = Group(title=form.title.data, text=form.text.data,
                    publish_date=datetime.now(),
                    user_id=current_user.id)
        db.session.add(group)
        group.users.append(current_user)
        db.session.commit()

        #flash('Group added!')

        return redirect(url_for('group'))

    return render_template('add_group.html', form=form)


@app.route('/join_group/<int:g_id>', methods=('GET', 'POST'))
@login_required
def join_group(g_id):
    group = Group.query.filter_by(id=g_id).first()
    group.users.append(current_user)
    db.session.commit()

    return redirect(url_for('group'))
