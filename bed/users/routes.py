from flask import render_template, Blueprint, url_for, flash, redirect, request, g, jsonify
from bed.users.forms import SignUpForm, LoginForm, User, Role, ResetPasswordForm, RequestResetForm, PostingForm
from bed import bcrypt, db
from flask_login import current_user, login_user, logout_user, login_required, current_user
import uuid
from sqlalchemy.exc import IntegrityError
from flask import session
from flask_login import LoginManager
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
from sqlalchemy import func

users = Blueprint("users", __name__)


class hospitals(db.Model):
    __tablename__ = 'Hospitals'
    id = db.Column(db.Integer, primary_key=True)
    hospital_id = db.Column(db.String(255))
    name = db.Column(db.String(255))
    address = db.Column(db.String(255))
    phone_no = db.Column(db.String(255))
    classification = db.Column(db.String(255))
    no_of_wards = db.Column(db.String(255))

class ward_name(db.Model):
    __tablename__ = 'Ward_name'
    id = db.Column(db.Integer, primary_key=True)
    hospital_id = db.Column(db.String(255))
    ward_no = db.Column(db.Integer)
    ward_name = db.Column(db.String(255))
    ward_description = db.Column(db.String(255))
    location = db.Column(db.String(255))

class ward(db.Model):
    __tablename__ = 'Ward'
    id = db.Column(db.Integer, primary_key=True)
    hospital_id = db.Column(db.String(255))
    ward_no = db.Column(db.Integer)
    ward_name = db.Column(db.String(255))
    total_beds = db.Column(db.Integer)
    free_beds = db.Column(db.Integer)
    user_id = db.Column(db.String(255))

@users.route("/")
def home():
    return render_template('index.html')



@users.route("/Hospital")
def Hospital():
    return render_template('Hospital.html')