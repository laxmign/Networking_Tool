from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# Define the Role model
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))

    # Relationships
    users = db.relationship('User', backref='role', lazy=True)

    def __repr__(self):
        return f'<Role {self.name}>'

# Define the User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    

    # Relationships
    profile = db.relationship('Profile', backref='user', uselist=False)
    backups = db.relationship('BackupStatus', backref='user', lazy=True)
    activities = db.relationship('ActivityLog', backref='user', lazy=True)
    versions = db.relationship('ConfigurationVersion', backref='user', lazy=True)
    config_profiles = db.relationship('ConfigurationProfile', backref='user', lazy=True)
    deployment_history = db.relationship('DeploymentHistory', backref='user', lazy=True)
   

    def __repr__(self):
        return f'<User {self.email}>'

# Define the Profile model
class Profile(db.Model):
    __tablename__ = 'profiles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    bio = db.Column(db.String(255))
    profile_picture = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Profile {self.user_id}>'

# Define the LoginHistory model
class LoginHistory(db.Model):
    __tablename__ = 'login_history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))  # Support for both IPv4 and IPv6 addresses

    def __repr__(self):
        return f'<LoginHistory {self.user_id} logged in at {self.login_time}>'

# Function to create default roles if they don't exist
def create_roles():
    # Check if roles already exist
    if not Role.query.filter_by(name='Admin').first():
        admin_role = Role(name='Admin', description='Administrator with full access')
        db.session.add(admin_role)
    
    if not Role.query.filter_by(name='User').first():
        user_role = Role(name='User', description='Regular user with limited access')
        db.session.add(user_role)
    
    db.session.commit()
    print("Roles ensured successfully.")


# Define the ConfigurationBackup model
class ConfigurationBackup(db.Model):
    __tablename__ = 'config_backups'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    config_data = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ConfigurationBackup {self.id} by User {self.user_id}>'
    
class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), default='offline')
    cpu = db.Column(db.String(10), default='0%')
    memory = db.Column(db.String(10), default='0%')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Device {self.name}>'
    
# models.py

class BackupStatus(db.Model):
    __tablename__ = 'backup_status'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50))  # e.g., 'Success', 'Failed'
    message = db.Column(db.String(255))  # Optional message about the backup result
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # Link to the user

    def __repr__(self):
        return f'<BackupStatus {self.status} at {self.timestamp}>'
    
# models.py

class ActivityLog(db.Model):
    __tablename__ = 'activity_log'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __repr__(self):
        return f'<ActivityLog {self.description} at {self.timestamp}>'
    

# Define the ConfigurationProfile model
class ConfigurationProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    profile_name = db.Column(db.String(100), nullable=False)
    profile_data = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Corrected foreign key
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    deployments = db.relationship('DeploymentHistory', backref='profile', lazy=True)

class ConfigurationVersion(db.Model):
    __tablename__ = 'configuration_versions'
    id = db.Column(db.Integer, primary_key=True)
    version_number = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ConfigurationVersion {self.version_number}>'


# Define the DeploymentHistory model
class DeploymentHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey('configuration_profile.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Corrected foreign key
    deployed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)