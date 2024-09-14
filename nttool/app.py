from flask import Flask, jsonify, render_template, request, redirect, session, url_for, flash
from models import db, User, Role  # Import your models here
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_migrate import Migrate

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Use a random secret key for added security

# Ensure the instance folder exists
if not os.path.exists('instance'):
    os.makedirs('instance')

# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)  # Initialize SQLAlchemy
migrate = Migrate(app, db)  # Initialize Flask-Migrate

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('emailID')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('FirstName')
        last_name = request.form.get('LastName')
        email = request.form.get('emailID')
        password = request.form.get('password')
        confirm_password = request.form.get('ConfirmPassword')

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        # Check if the email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))

        # Ensure default roles exist
        admin_role = Role.query.filter_by(name='Admin').first()
        user_role = Role.query.filter_by(name='User').first()

        if not user_role:
            # Create default roles if they don't exist
            admin_role = Role(name='Admin', description='Administrator with full access')
            user_role = Role(name='User', description='Regular user with limited access')
            db.session.add(admin_role)
            db.session.add(user_role)
            db.session.commit()

        # Hash the password and create a new user with the default "User" role
        hashed_password = generate_password_hash(password)
        new_user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password, role_id=user_role.id)

        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    # If it's a GET request, render the registration page
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    # Check if user is logged in by verifying the session
    if 'user_id' not in session:
        flash('Please log in first', 'danger')
        return redirect(url_for('login'))

    # Retrieve the user details
    user = User.query.get(session['user_id'])

    # Render the dashboard template with the user object
    return render_template('dashboard.html', user=user)



@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
     return render_template('contact.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            # Logic to handle password reset, such as sending an email with a reset link
            flash('Password reset instructions have been sent to your email.', 'success')
        else:
            flash('Email not found', 'danger')
    return render_template('forgot_password.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'danger')
    return redirect(url_for('login'))


@app.route('/versionhistory')

def version_history():
    if 'user_id' not in session:
        flash('Please log in first', 'danger')
        return redirect(url_for('login'))
    return render_template('versionhistory.html')

@app.route('/monitorintegration')
def monitor_integration():
    if 'user_id' not in session:
        flash('Please log in first', 'danger')
        return redirect(url_for('login'))
    return render_template('monitorintegration.html')

@app.route('/configurationdeployment')

def configuration_deployment():
    if 'user_id' not in session:
        flash('Please log in first', 'danger')
        return redirect(url_for('login'))
    return render_template('configurationdeployment.html')

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        flash('Please log in first', 'danger')
        return redirect(url_for('login'))
    
    user_id = session['user_id']  # Get the user_id from the session
    return render_template('settings.html', user_id=user_id)


@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user_details(user_id):
    try:
        # Query the database for the user with the given user_id
        user = User.query.get(user_id)
        
        if user is None:
            return jsonify({"message": "User not found"}), 404

        # Prepare the user details to return
        user_data = {
            'id': user.id,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'role': user.role.name if user.role else None,
            'profile': {
                'bio': user.profile.bio if user.profile else None,
                'website': user.profile.website if user.profile else None
            } if user.profile else None
        }
        
        return jsonify(user_data)

    except Exception as e:
        return jsonify({"message": str(e)}), 500


# Run the application
if __name__ == '__main__':
    app.run(debug=True)
