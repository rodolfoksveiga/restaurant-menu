# import packages
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length, EqualTo

# login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(),
                                                   Length(min=5, max=15)])
    password = PasswordField('Password', validators=[InputRequired(),
                                                     Length(min=8, max=80)])
    remember = BooleanField('Remember me')

# signup form
class SignupForm(FlaskForm):
    username = StringField('Username:', validators=[
        InputRequired(),
        Length(min=5, max=15)
    ])
    password = PasswordField('Password:', validators=[
        InputRequired(),
        Length(min=8, max=80),
        EqualTo('confirm', message='Passwords must match.')
    ])
    confirm = PasswordField('Confirm password:', validators=[
        InputRequired(),
        Length(min=8, max=80)
    ])
    email = StringField('Email:', validators=[
        InputRequired(),
        Email(message='Invalid email.'),
        Length(min=3, max=50)
    ])
    name = StringField('Name:', validators=[
        InputRequired(),
        Length(min=2, max=50)
    ])

class ChangePassword(FlaskForm):
    old = PasswordField('Old password:', validators=[
        InputRequired(),
        Length(min=8, max=80)
    ])
    new = PasswordField('New password:', validators=[
        InputRequired(),
        Length(min=8, max=80),
        EqualTo('confirm', message='Passwords must match.')
    ])
    confirm = PasswordField('Confirm new password:', validators=[
        InputRequired(),
        Length(min=8, max=80)
    ])