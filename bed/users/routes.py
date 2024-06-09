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
    ward_desc = db.Column(db.String(255))
    location = db.Column(db.String(255))

class ward(db.Model):
    __tablename__ = 'Ward'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    hospital_id = db.Column(db.String(255))
    ward_no = db.Column(db.Integer)
    ward_name = db.Column(db.String(255))
    total_beds = db.Column(db.Integer)
    free_beds = db.Column(db.Integer)
    user_id = db.Column(db.String(255))



def table_to_dict(database_name):
    # Retrieve all rows from the 'Laptop_listings' table
    rows = database_name.query.all()

    # Get the columns of the 'Laptop_listings' table
    columns = database_name.__table__.columns.keys()

    # Initialize an empty dictionary to store the table data
    table_data = {column: [] for column in columns}

    # Populate the dictionary with data from each row
    for row in rows:
        for column in columns:
            # Get the value of the current column for the current row
            value = getattr(row, column)
            # Append the value to the corresponding list in the dictionary
            table_data[column].append(value)

    return table_data



def table_to_dictionary(table):
    """
    Convert a table to a dictionary.
    Each key in the dictionary will correspond to a column name and 
    the associated value will be a list of all entries in that column.
    """
    result = {col: [] for col in table[0].keys()}  # Initialize a dictionary with empty lists for each column

    for row in table:
        for col, val in row.items():
            result[col].append(val)  # Append each cell value to the corresponding column list
    
    return result


@users.route("/")
def home():
    Hospitals = table_to_dict(hospitals)
    full_name= None
    if current_user.is_authenticated:
        full_name = current_user.first_name + ' ' + current_user.last_name
    # Pass the laptop_parts list to the template
    return render_template('index.html', full_name=full_name, Hospitals=Hospitals)



@users.route("/Hospital/<clinic_id>")
def Hospital(clinic_id):
    Ward_name = table_to_dict(ward_name)
    Hospitals = table_to_dict(hospitals)
    full_name= None
    if current_user.is_authenticated:
        full_name = current_user.first_name + ' ' + current_user.last_name
    return render_template('Hospital.html', full_name=full_name, Ward_name=Ward_name, clinic_id=clinic_id, Hospitals=Hospitals)


@users.route("/Ward/<ward_id>/<clinic_id>")
def Ward(ward_id, clinic_id):
    wards = table_to_dict(ward)
    Hospitals = table_to_dict(hospitals)
    full_name= None
    if current_user.is_authenticated:
        full_name = current_user.first_name + ' ' + current_user.last_name
    return render_template('Ward.html', full_name=full_name, wards=wards, ward_id=ward_id, Hospitals=Hospitals, clinic_id=clinic_id)


@users.route('/signup', methods=['GET', 'POST'])
def sign_up():
    form = SignUpForm()
    if form.validate_on_submit():
        # Check if the email already exists
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already exists', 'danger')
        else:
            # created bt coker Proceed with creating a new user if the email doesn't exist
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


@users.route("/logout")
def logout():
    """Logout a logged-in user"""
    logout_user()
    session.clear()  # Clear session data
    return redirect(url_for('users.login'))


@users.route("/posting")
def posting():
    form = PostingForm()
    full_name= None
    if current_user.is_authenticated:
        full_name = current_user.first_name + ' ' + current_user.last_name
    return render_template('post.html', full_name=full_name, form=form)


@users.route("/submit_bed", methods=['POST'])
def submit_bed():
    if current_user.is_authenticated:
        ward_name = request.form.get('Ward_name')
        ward_no = request.form.get('Ward_no')
        total_beds = request.form.get('total_beds')
        free_beds = request.form.get('free_beds')

        users = table_to_dict(User)
        for i in range(len(users['id'])):
            if users['id'][i] == current_user.id:
                if users['hospital_id'][i]:
                    hospital_id = users['hospital_id'][i]

                    # Get the maximum id value
                    max_id = db.session.query(func.max(ward.id)).scalar()

                    # Set the new id to be one more than the maximum id value
                    new_id = int(max_id) + 1 if max_id else 1

                    # Check if the ward with the same hospital_id and ward_no exists
                    existing_ward = ward.query.filter_by(hospital_id=hospital_id, ward_no=ward_no).first()

                    if existing_ward:
                        # Update the existing ward
                        existing_ward.ward_name = ward_name
                        existing_ward.total_beds = total_beds
                        existing_ward.free_beds = free_beds
                    else:
                        # Create a new ward
                        new_ward = ward(
                            id = new_id,
                            hospital_id=hospital_id,
                            ward_name=ward_name,
                            ward_no=ward_no,
                            total_beds=total_beds,
                            free_beds=free_beds,
                            user_id=current_user.id
                        )
                        db.session.add(new_ward)

                    db.session.commit()
                    flash('Ward data submitted successfully', 'success')
                else:
                    flash('Permission denied', 'error')
            else:
                flash('You need to be logged in to submit bed data', 'error')

    return redirect(url_for('users.posting'))
