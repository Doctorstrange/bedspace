from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from bed import db, login_manager
from flask_login import UserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app
from sqlalchemy import UniqueConstraint
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash

""" User class"""
user_role = db.Table('users_roles',
                     db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
                     db.Column('role_id', db.Integer, db.ForeignKey('role.id')))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


class User(UserMixin, db.Model):
    id = db.Column(db.String(36), primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(128), nullable=False)  # Changed column name
    role = db.Column(db.Boolean, default=True)
    is_active = db.Column(db.Boolean, default=True)
    hospital_id = db.Column(db.Integer)

    __table_args__ = (
        UniqueConstraint('email', name='unique_email'),
    )

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def get_id(self):
        return self.id




class PostingForm(FlaskForm):
    Ward_name = StringField('Name of word', validators=[DataRequired()])
    Ward_no = StringField('Number of word', validators=[DataRequired()])
    total_beds = StringField('Total beds')
    free_beds= StringField('Free beds', validators=[DataRequired()])




class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False, unique=True)
    role_description = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return "Role('{}', '{}', '{}')" \
            .format(self.id, self.name, self.role_description)

class SignUpForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class RequestResetForm(FlaskForm):
    """Reset Form"""
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password_reset = StringField("Request Password Reset")
    submit = SubmitField("Send")

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

