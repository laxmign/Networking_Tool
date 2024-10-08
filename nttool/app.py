
from datetime import datetime, timedelta
import random
import json
import os
import threading
from time import sleep
from flask_socketio import SocketIO, emit
from flask import Flask,jsonify, render_template, request, redirect, send_file, session, url_for, flash
from models import (
    ActivityLog, BackupStatus, ConfigurationBackup, ConfigurationProfile, 
    ConfigurationVersion, DeploymentHistory, Device, db, User, Role, Profile, 
    LoginHistory
)
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_migrate import Migrate
from functools import wraps
from deepdiff import DeepDiff

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
            
            # flash('Login successful!', 'success')
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


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.json
    user_id = data.get('user_id')
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    # Fetch the user from the database
    user = User.query.get(user_id)

    if not user:
        return jsonify({"success": False, "message": "User not found."}), 404

    # Check if the current password is correct
    if not check_password_hash(user.password, current_password):
        return jsonify({"success": False, "message": "Current password is incorrect."}), 400

    # If the current password is correct, update to the new password
    hashed_password = generate_password_hash(new_password)
    user.password = hashed_password

    # Commit the changes to the database
    try:
        db.session.commit()
        return jsonify({"success": True, "message": "Password changed successfully."}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

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
    identifier = data.get('identifier')

    try:
        # Randomly set the device status to 'online' or 'offline'
        status = random.choice(['online', 'offline'])

        # If the device is offline, set lower CPU and memory usage
        if status == 'offline':
            cpu_usage = f"{random.randint(0, 30)}%"
            memory_usage = f"{random.randint(0, 30)}%"
        else:
            # If the device is online, allow full CPU and memory range
            cpu_usage = f"{random.randint(0, 100)}%"
            memory_usage = f"{random.randint(0, 100)}%"

        # Create a new device with the generated status, CPU, memory usage, and the user ID
        new_device = Device(
            name=name,
            ip_address=identifier,
            status=status,
            cpu=cpu_usage,
            memory=memory_usage,
            user_id=session['user_id'],
        )
        db.session.add(new_device)
        db.session.commit()

        return jsonify({"message": f"Device '{name}' added successfully"}), 201

    except Exception as e:
        db.session.rollback()
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
def device_performance():
    try:
        # Get the current user ID from the session
        user_id = session['user_id']

        # Query the Device model to get all devices for the logged-in user
        devices = Device.query.filter_by(user_id=user_id).all()

        # Format the device data into a JSON-friendly structure
        devices_data = [
            {
                'name': device.name,
                'ip': device.ip_address,
                'status': device.status,
                'cpu': device.cpu,
                'memory': device.memory
            }
            for device in devices
        ]

        # Return the device data as a JSON response
        return jsonify(devices_data), 200

    except Exception as e:
        return jsonify({"message": str(e)}), 500

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


@app.route('/compare_version/<int:version_id>', methods=['GET', 'POST'])
@login_required
def compare_version(version_id):
    version = ConfigurationVersion.query.get(version_id)
    
    if not version:
        flash('Version not found', 'danger')
        return redirect(url_for('version_history'))

    if request.method == 'POST':
        second_version_id = request.form.get('second_version_id')

        if not second_version_id:
            flash('Please select a second version for comparison.', 'warning')
            return redirect(url_for('compare_version', version_id=version_id))

        if not second_version_id.isdigit():
            flash('Invalid version selected for comparison', 'danger')
            return redirect(url_for('compare_version', version_id=version_id))

        if int(second_version_id) == version_id:
            flash('Cannot compare the same version with itself. Please select a different version.', 'danger')
            return redirect(url_for('compare_version', version_id=version_id))

        second_version = ConfigurationVersion.query.get(second_version_id)

        if not second_version:
            flash('The second version to compare was not found', 'danger')
            return redirect(url_for('compare_version', version_id=version_id))

        if not version.description or not second_version.description:
            flash('One or both versions have no description to compare.', 'danger')
            return redirect(url_for('compare_version', version_id=version_id))

        try:
            json_1 = json.loads(version.description)
            json_2 = json.loads(second_version.description)
        except json.JSONDecodeError:
            flash('Invalid JSON format in one or both versions', 'danger')
            return redirect(url_for('compare_version', version_id=version_id))

        differences = DeepDiff(json_1, json_2, ignore_order=True).to_dict()

        if not differences:
            flash('No differences found between the two versions', 'info')

        return render_template('compare_version.html', version=version, second_version=second_version, differences=differences)

    all_versions = ConfigurationVersion.query.filter(ConfigurationVersion.id != version_id).all()
    return render_template('compare_version.html', version=version, all_versions=all_versions)



@app.route('/create_version', methods=['POST'])
@login_required  # Ensure the user is logged in
def create_version():
    version_number = request.form.get('version_name')
    version_description = request.form.get('version_description')  # Get the description from the form

    # Validate input
    if not version_number:
        flash('Version name is required',  ('version','danger'))
        return redirect(url_for('version_history'))

    # Validate JSON format for description
    try:
        json_description = json.loads(version_description)  # Try to parse the description as JSON
    except json.JSONDecodeError:
        flash('Description must be a valid JSON format', ('version','danger'))
        return redirect(url_for('version_history'))

    try:
        # Create new version entry with the description stored as JSON
        new_version = ConfigurationVersion(
            version_number=version_number,
            user_id=session['user_id'],  # User ID from session
            created_at=datetime.now(),  # Automatically handled by default in the model
            description=json.dumps(json_description)  # Store the description as a JSON string
        )
        db.session.add(new_version)  # Add the new version to the session

        # Log the activity for creating a new version
        activity = ActivityLog(
            user_id=session['user_id'],
            description=f"Import new version {version_number} with JSON description"
        )
        db.session.add(activity)  # Add the activity log to the session

        # Commit both the new version and the activity log
        db.session.commit()

        flash(f'Version {version_number} imported successfully with valid JSON description!',  ('version','success'))
    except Exception as e:
        db.session.rollback()  # Rollback changes if there is an error
        flash(f'Error creating version: {str(e)}',  ('version','danger'))
    
    return redirect(url_for('version_history'))

@app.route('/delete_version/<int:version_id>', methods=['POST'])
@login_required
def delete_version(version_id):
    try:
        # Fetch the version by its ID
        version_to_delete = ConfigurationVersion.query.get(version_id)
        
        if version_to_delete:
            # Delete the version
            db.session.delete(version_to_delete)

            # Log the deletion activity
            activity = ActivityLog(
                user_id=session['user_id'],
                description=f"Deleted version {version_to_delete.version_number}"
            )
            db.session.add(activity)

            # Commit the changes to the database
            db.session.commit()
            flash(f'Version {version_to_delete.version_number} deleted successfully.', 'success')
        else:
            flash('Version not found.', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting version: {str(e)}', 'danger')

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
            timestamp=datetime.now()
        )
        db.session.add(new_backup)  # Add the new backup to the session

        # Log the activity for creating a new backup
        activity = ActivityLog(
            user_id=session['user_id'],
            description="Backup process initiated"
        )
        db.session.add(activity)  

       
        db.session.commit()

        # Delay for 2-3 seconds
        sleep(3)

        # Update the status to 'Completed'
        new_backup.status = 'Completed'
        new_backup.message = 'Backup completed successfully'
        new_backup.timestamp =datetime.now()
        db.session.commit()

        flash('Backup created successfully!',  ('backup','success'))
    except Exception as e:
        db.session.rollback()  # Rollback changes if there is an error
        flash(f'An error occurred while creating the backup: {str(e)}',  ('backup','danger'))

    return redirect(url_for('backup_status'))

@app.route('/download_backup/<int:backup_id>')
@login_required
def download_backup(backup_id):
    # Fetch the backup by ID
    backup = BackupStatus.query.get(backup_id)

    if not backup:
        flash('Backup not found',  ('backup','Success'))
        return redirect(url_for('backup_status'))

    # Example file path for the backup
    backup_file_path = os.path.join(app.root_path, 'static', 'backup', f'{backup_id}.zip')

    try:
        # Flash success message when the backup is successfully found
        flash(f'Successfully Downloaded backup {backup_id}',  ('backup','success'))
        return send_file(backup_file_path, as_attachment=True)
    except Exception as e:
       return redirect(url_for('backup_status'))


@app.route('/restore_version/<int:version_id>')
@login_required
def restore_version(version_id):
    version = ConfigurationVersion.query.get(version_id)
    if not version:
        flash('Version not found',  ('backup','danger'))
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

        flash('Configuration restored successfully!',('version', 'success'))
    except Exception as e:
        db.session.rollback()
        flash(f'Error restoring configuration version: {str(e)}', ('version', 'danger'))

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

        # Validation: Check if profile_data is valid JSON
        try:
            json.loads(profile_data)  # Try parsing the profile data as JSON
        except ValueError:
            flash('Profile data must be valid JSON', ('deployment', 'danger'))
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
            flash(f'Profile {profile_name} created successfully!', ('deployment', 'success'))

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
   



if __name__ == '__main__':
    threading.Thread(target=generate_network_data, daemon=True).start()
    threading.Thread(target=generate_device_data, daemon=True).start()
    socketio.run(app, debug=True)