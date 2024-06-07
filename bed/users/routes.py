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


@users.route('/signup', methods=['GET', 'POST'])
def sign_up():
    form = SignUpForm()
    if form.validate_on_submit():
        # Check if the email already exists
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already exists', 'danger')
        else:
            # Proceed with creating a new user if the email doesn't exist
            user_id = str(uuid.uuid4())
            # Hash the password before storing it
            hashed_password = generate_password_hash(form.password.data)
            new_user = User(id=user_id,
                            email=form.email.data,
                            first_name=form.first_name.data,
                            last_name=form.last_name.data,
                            password=hashed_password)  # Store the hashed password
            try:
                db.session.add(new_user)
                db.session.commit()
                flash('Account created successfully!', 'success')
                return redirect(url_for('users.login'))
            except IntegrityError:
                db.session.rollback()
                flash('An error occurred while creating your account. Please try again.', 'danger')
    return render_template('signup.html', form=form)



@users.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            # Populate the user object with additional attributes
            user_data = {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            }
            # Add user data to the session
            session['user'] = user_data
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('users.home'))
        else:
            flash('Login unsuccessful. Please check your email and password.', 'danger')
    return render_template('login.html', form=form)
