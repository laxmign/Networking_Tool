from datetime import datetime
import random
import threading
from flask_socketio import SocketIO, emit
from flask import Flask, jsonify, render_template, request, redirect, send_file, session, url_for, flash
from models import (
    ActivityLog, BackupStatus, ConfigurationBackup, ConfigurationProfile, 
    ConfigurationVersion, DeploymentHistory, Device, db, User, Role, Profile, 
    LoginHistory
)
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_migrate import Migrate
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app)

# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
migrate = Migrate(app, db)

# Helper functions
def login_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first', 'danger')
            return redirect(url_for('login'))
        return route_function(*args, **kwargs)
    return wrapper

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
            
            # Log the login history
            login_history = LoginHistory(user_id=user.id, ip_address=request.remote_addr)
            db.session.add(login_history)

            # Log the login activity in the activity log
            activity = ActivityLog(user_id=user.id, description="User logged in")
            db.session.add(activity)

            # Commit both login history and activity log to the database
            db.session.commit()
            
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

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))

        user_role = Role.query.filter_by(name='User').first()
        if not user_role:
            admin_role = Role(name='Admin', description='Administrator with full access')
            user_role = Role(name='User', description='Regular user with limited access')
            db.session.add_all([admin_role, user_role])
            db.session.commit()

        hashed_password = generate_password_hash(password)
        new_user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password, role_id=user_role.id)

        db.session.add(new_user)
        db.session.commit()
        
        # Create a profile for the new user
        new_profile = Profile(user_id=new_user.id)
        db.session.add(new_profile)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            # TODO: Implement password reset logic
            flash('Password reset instructions have been sent to your email.', 'success')
        else:
            flash('Email not found', 'danger')
        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    devices = Device.query.all()
    return render_template('dashboard.html', user=user, devices=devices)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
     return render_template('contact.html')

@app.route('/logout')
@login_required  # Optional: Ensures that only logged-in users can log out
def logout():
    user_id = session.get('user_id')
    
    if user_id:
        # Log the logout activity before clearing the session
        activity = ActivityLog(user_id=user_id, description="User logged out")
        db.session.add(activity)
        db.session.commit()

    # Clear the session
    session.pop('user_id', None)
    
    flash('You have been logged out.', 'danger')
    return redirect(url_for('login'))
@app.route('/settings')
@login_required
def settings():
    user_id = session['user_id']
    user = User.query.get(user_id)
    return render_template('settings.html', user=user)

@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user_details(user_id):
    try:
        user = User.query.get(user_id)
        
        if user is None:
            return jsonify({"message": "User not found"}), 404

        user_data = {
            'id': user.id,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'role': user.role.name if user.role else None,
            'profile': {
                'bio': user.profile.bio if user.profile else None,
                'profile_picture': user.profile.profile_picture if user.profile else None
            } if user.profile else None
        }
        
        return jsonify(user_data)

    except Exception as e:
        return jsonify({"message": str(e)}), 500

@app.route('/versionhistory')
@login_required
def version_history():
    backups = ConfigurationBackup.query.filter_by(user_id=session['user_id']).all()
    versions = ConfigurationVersion.query.filter_by(user_id=session['user_id']).all()
    return render_template('versionhistory.html', backups=backups, versions=versions)

@app.route('/restore_backup/<int:backup_id>')
@login_required
def restore_backup(backup_id):
    backup = ConfigurationBackup.query.get(backup_id)
    if not backup:
        flash('Backup not found', 'danger')
        return redirect(url_for('version_history'))

    # TODO: Implement restore logic
    flash('Backup restored successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/monitorintegration')
@login_required
def monitor_integration():
    return render_template('monitorintegration.html')

@app.route('/admin_only')
@login_required
def admin_only():
    user = User.query.get(session['user_id'])
    if user.role.name != 'Admin':
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('dashboard'))

    return render_template('admin_dashboard.html')

@app.route('/backup_status')
@login_required
def backup_status():
    backups = BackupStatus.query.filter_by(user_id=session['user_id']).order_by(BackupStatus.timestamp.desc()).all()
    return render_template('backup_status.html', backups=backups)

@app.route('/add_user_device', methods=['POST'])
@login_required
def add_user_device():
    data = request.json
    name = data.get('name')
    type_ = data.get('type')
    identifier = data.get('identifier')

    try:
        if type_ == 'device':
            new_device = Device(name=name, ip_address=identifier)
            db.session.add(new_device)
        elif type_ == 'user':
            new_user = User(first_name=name, email=identifier, password='default_password')
            db.session.add(new_user)
        else:
            return jsonify({"message": "Invalid type."}), 400

        db.session.commit()
        return jsonify({"message": f"{type_.capitalize()} added successfully."}), 201

    except Exception as e:
        return jsonify({"message": str(e)}), 500

# SocketIO events
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('message')
def handle_message(message):
    print('Received message:', message)
    emit('message', message, broadcast=True)

@socketio.on('get_device_performance')
def handle_get_device_performance():
    emit('device_status_update', devices)

@socketio.on('get_network_status')
def handle_get_network_status():
    emit('network_status_update', get_network_status())

network_status = {
    'connected': True,
    'uptime': datetime.now(),
    'performance': 'Good'
}

devices = {
    'Router': {'status': 'online', 'cpu': '0%', 'memory': '0%'},
    'Switch': {'status': 'online', 'cpu': '0%', 'memory': '0%'},
    'Server': {'status': 'online', 'cpu': '0%', 'memory': '0%'}
}

def get_network_status():
    uptime = datetime.now() - network_status['uptime']
    days, seconds = uptime.days, uptime.seconds
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    return {
        'connected': network_status['connected'],
        'uptime': f"{days} days, {hours} hours, {minutes} minutes",
        'performance': network_status['performance']
    }

def generate_network_data():
    global network_status
    while True:
        network_status['connected'] = random.choice([True, False])
        network_status['performance'] = random.choice(['Good', 'Fair', 'Poor'])
        socketio.emit('network_status_update', get_network_status())
        socketio.sleep(10)

def generate_device_data():
    while True:
        for device in devices:
            devices[device]['cpu'] = f"{random.randint(0, 100)}%"
            devices[device]['memory'] = f"{random.randint(0, 100)}%"
            devices[device]['status'] = random.choice(['online', 'offline'])
        socketio.emit('device_status_update', devices)
        socketio.sleep(60)

@app.route('/device_performance', methods=['GET'])
@login_required
def get_device_performance():
    try:
        devices = Device.query.all()
        device_data = []
        for device in devices:
            device_data.append({
                'name': device.name,
                'ip': device.ip_address,
                'status': device.status,
                'cpu': device.cpu,
                'memory': device.memory
            })
        return jsonify(device_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/recent_activity', methods=['GET', 'POST'])
@login_required
def recent_activity():
    # Get filter parameters from request arguments (for GET requests)
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    activity_type = request.args.get('activity_type')

    # Initialize query to filter activities based on the current user
    activities_query = ActivityLog.query.filter_by(user_id=session['user_id'])

    # Apply the filters if the user has set them
    if start_date:
        activities_query = activities_query.filter(ActivityLog.timestamp >= start_date)
    if end_date:
        activities_query = activities_query.filter(ActivityLog.timestamp <= end_date)
    if activity_type:
        activities_query = activities_query.filter(ActivityLog.type == activity_type)
    
    # Order the results by timestamp
    activities = activities_query.order_by(ActivityLog.timestamp.desc()).all()

    # Render the template with the filtered activities
    return render_template('recent_activity.html', activities=activities)


@app.route('/compare_version/<int:version_id>')
@login_required
def compare_version(version_id):
    # TODO: Implement version comparison logic
    version = ConfigurationVersion.query.get(version_id)
    if not version:
        flash('Version not found', 'danger')
        return redirect(url_for('version_history'))
    
    # For now, just display the version details
    return render_template('compare_version.html', version=version)


@app.route('/create_version', methods=['POST'])
@login_required  # Ensure the user is logged in
def create_version():
    version_number = request.form.get('version_name')

    # Validate input
    if not version_number:
        flash('Version name is required', 'danger')
        return redirect(url_for('version_history'))

    try:
        # Create new version entry
        new_version = ConfigurationVersion(
            version_number=version_number,
            user_id=session['user_id'],  # User ID from session
            created_at=datetime.utcnow()  # Automatically handled by default in the model
        )
        db.session.add(new_version)  # Add the new version to the session

        # Log the activity for creating a new version
        activity = ActivityLog(
            user_id=session['user_id'],
            description=f"Created new version {version_number}"
        )
        db.session.add(activity)  # Add the activity log to the session

        # Commit both the new version and the activity log
        db.session.commit()

        flash(f'Version {version_number} created successfully!', 'success')
    except Exception as e:
        db.session.rollback()  # Rollback changes if there is an error
        flash(f'Error creating version: {str(e)}', 'danger')
    
    return redirect(url_for('version_history'))

@app.route('/create_backup', methods=['POST'])
@login_required
def create_backup():
    try:
        # Create a new backup entry with an initial "In Progress" status
        new_backup = BackupStatus(
            user_id=session['user_id'],
            status='In Progress',  # Initial status, can be updated later
            message='Backup initiated',
            timestamp=datetime.utcnow()
        )
        db.session.add(new_backup)  # Add the new backup to the session

        # Log the activity for creating a new backup
        activity = ActivityLog(
            user_id=session['user_id'],
            description="Backup process initiated"
        )
        db.session.add(activity)  # Add the activity log to the session

        # Commit both the new backup and the activity log
        db.session.commit()

        flash('Backup created successfully!', 'success')
    except Exception as e:
        db.session.rollback()  # Rollback changes if there is an error
        flash(f'An error occurred while creating the backup: {str(e)}', 'danger')

    return redirect(url_for('backup_status'))


@app.route('/download_backup/<int:backup_id>')
@login_required
def download_backup(backup_id):
    # Fetch the backup by ID
    backup = BackupStatus.query.get(backup_id)

    if not backup:
        flash('Backup not found', 'danger')
        return redirect(url_for('backup_status'))

   
    
    backup_file_path = f"/path/to/backups/{backup_id}.zip"  # Example file path for the backup
    try:
        return send_file(backup_file_path, as_attachment=True)
    except FileNotFoundError:
        flash('Backup file not found', 'danger')
        return redirect(url_for('backup_status'))


@app.route('/restore_version/<int:version_id>')
@login_required
def restore_version(version_id):
    version = ConfigurationVersion.query.get(version_id)
    if not version:
        flash('Version not found', 'danger')
        return redirect(url_for('version_history'))

    try:
        
        # Log the activity for restoring the configuration version
        activity = ActivityLog(
            user_id=session['user_id'],
            description=f"Restored configuration version {version.version_number}"
        )
        db.session.add(activity)

        # Commit the activity log
        db.session.commit()

        flash('Configuration restored successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error restoring configuration version: {str(e)}', 'danger')

    return redirect(url_for('version_history'))
@app.route('/configuration_deployment', methods=['GET', 'POST'])
@login_required
def configuration_deployment():
    if request.method == 'POST':
        profile_name = request.form.get('profile_name')
        profile_data = request.form.get('profile_data')

        # Validation: Ensure both profile name and data are present
        if not profile_name or not profile_data:
            flash('Both profile name and data are required', ('deployment', 'danger'))
            return redirect(url_for('configuration_deployment'))

        # Try to create a new profile
        try:
            new_profile = ConfigurationProfile(
                profile_name=profile_name,
                profile_data=profile_data,
                user_id=session['user_id']
            )
            db.session.add(new_profile)

            # Log the activity for creating a new configuration profile
            activity = ActivityLog(
                user_id=session['user_id'],
                description=f"Created configuration profile '{profile_name}'"
            )
            db.session.add(activity)

            # Commit both the new profile and the activity log
            db.session.commit()
            flash(f'Profile {profile_name} created successfully!',('deployment', 'success'))

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', ('deployment', 'danger'))

        # Redirect to avoid form resubmission on page refresh
        return redirect(url_for('configuration_deployment'))

    # Fetch existing profiles and deployment history for the GET request
    profiles = ConfigurationProfile.query.filter_by(user_id=session['user_id']).all()
    deployment_history = DeploymentHistory.query.filter_by(user_id=session['user_id']).order_by(DeploymentHistory.deployed_at.desc()).all()

    # Render the configuration deployment page with profiles and history
    return render_template('configuration_deployment.html', profiles=profiles, deployment_history=deployment_history)


@app.route('/deploy_profile/<int:profile_id>')
@login_required
def deploy_profile(profile_id):
    profile = ConfigurationProfile.query.filter_by(id=profile_id, user_id=session['user_id']).first()
    
    if not profile:
        flash('Profile not found or you do not have permission to deploy this profile.', ('deployment', 'danger'))
        return redirect(url_for('configuration_deployment'))

    try:
        deployment_history = DeploymentHistory(
            profile_id=profile.id,
            user_id=session['user_id']
        )
        db.session.add(deployment_history)
        db.session.commit()

        deploy_logic(profile)
        flash(f'Profile {profile.profile_name} deployed successfully!',  ('deployment', 'success'))
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while deploying the profile: {e}', ('deployment', 'danger'))

    return redirect(url_for('configuration_deployment'))

def deploy_logic(profile):
    print(f"Deploying profile: {profile.profile_name}")
    print(f"Configuration data: {profile.profile_data}")
    # TODO: Add real deployment logic here

if __name__ == '__main__':
    threading.Thread(target=generate_network_data, daemon=True).start()
    threading.Thread(target=generate_device_data, daemon=True).start()
    socketio.run(app, debug=True)