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
    login_history = db.relationship('LoginHistory', backref='user', lazy=True)

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
