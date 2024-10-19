from distutils.command.install import install

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager, create_access_token
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_roles.db'
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this in production
db = SQLAlchemy(app)
ma = Marshmallow(app)
jwt = JWTManager(app)


# Role model
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    roleName = db.Column(db.String(100), nullable=False, unique=True)
    accessModules = db.Column(db.PickleType, nullable=False)  # List of accessible modules
    createdAt = db.Column(db.DateTime, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)


# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(100), nullable=False)
    lastName = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    role = db.relationship('Role', backref=db.backref('users', lazy=True))


# Create the database tables
def create_tables():
    db.create_all()


class RoleSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Role


class UserSchema(ma.SQLAlchemyAutoSchema):
    role = ma.Nested(RoleSchema, only=("roleName", "accessModules"))

    class Meta:
        model = User


role_schema = RoleSchema()
roles_schema = RoleSchema(many=True)
user_schema = UserSchema()
users_schema = UserSchema(many=True)

#creating role module API CRUD
@app.route('/roles', methods=['POST'])
def create_role():
    role_name = request.json['roleName']
    access_modules = request.json['accessModules']
    new_role = Role(roleName=role_name, accessModules=access_modules)
    db.session.add(new_role)
    db.session.commit()
    return role_schema.jsonify(new_role)


@app.route('/roles', methods=['GET'])
def get_roles():
    roles = Role.query.all()
    return roles_schema.jsonify(roles)


@app.route('/roles/<id>', methods=['GET'])
def get_role(id):
    role = Role.query.get(id)
    return role_schema.jsonify(role)


@app.route('/roles/<id>', methods=['PUT'])
def update_role(id):
    role = Role.query.get(id)
    role.roleName = request.json['roleName']
    role.accessModules = request.json['accessModules']
    db.session.commit()
    return role_schema.jsonify(role)


@app.route('/roles/<id>', methods=['DELETE'])
def delete_role(id):
    role = Role.query.get(id)
    db.session.delete(role)
    db.session.commit()
    return jsonify({'message': 'Role deleted successfully'})

#Creat user module API
@app.route('/users', methods=['POST'])
def create_user():
    data = request.json
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(firstName=data['firstName'], lastName=data['lastName'], email=data['email'],
                    password=hashed_password, role_id=data['role_id'])
    db.session.add(new_user)
    db.session.commit()
    return user_schema.jsonify(new_user)

@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return users_schema.jsonify(users)

@app.route('/users/<id>', methods=['GET'])
def get_user(id):
    user = User.query.get(id)
    return user_schema.jsonify(user)

@app.route('/users/<id>', methods=['PUT'])
def update_user(id):
    user = User.query.get(id)
    data = request.json
    user.firstName = data['firstName']
    user.lastName = data['lastName']
    user.email = data['email']
    if 'password' in data:
        user.password = generate_password_hash(data['password'], method='sha256')
    user.role_id = data['role_id']
    db.session.commit()
    return user_schema.jsonify(user)

@app.route('/users/<id>', methods=['DELETE'])
def delete_user(id):
    user = User.query.get(id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'})

#Sign up and login API
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(firstName=data['firstName'], lastName=data['lastName'], email=data['email'],
                    password=hashed_password, role_id=data['role_id'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'})

#Login API
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        token = create_access_token(identity=user.id)
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials'}), 401

#Access module management
@app.route('/roles/<id>/modules', methods=['PUT'])
def update_access_modules(id):
    role = Role.query.get(id)
    role.accessModules = list(set(request.json['accessModules']))  # Ensuring unique modules
    db.session.commit()
    return role_schema.jsonify(role)

#Bulk module update
@app.route('/roles/<id>/modules/remove', methods=['POST'])
def remove_access_module(id):
    role = Role.query.get(id)
    module_to_remove = request.json['module']
    role.accessModules = [m for m in role.accessModules if m != module_to_remove]
    db.session.commit()
    return role_schema.jsonify(role)

@app.route('/users/<id>/has_access', methods=['POST'])
def has_access(id):
    user = User.query.get(id)
    module = request.json['module']
    if module in user.role.accessModules:
        return jsonify({'has_access': True})
    return jsonify({'has_access': False})


@app.route('/users/bulk/update_last_name', methods=['PUT'])
def bulk_update_last_name():
    new_last_name = request.json['abc']
    users = User.query.all()
    for user in users:
        user.lastName = new_last_name
    db.session.commit()
    return users_schema.jsonify(users)

#Search
@app.route('/users/bulk', methods=['PUT'])
def bulk_update():
    data = request.json
    for user_data in data:
        user = User.query.get(user_data['id'])
        user.firstName = user_data['firstName']
        user.lastName = user_data['lastName']
        user.email = user_data['email']
    db.session.commit()
    return users_schema.jsonify(User.query.all())

@app.route('/users/search', methods=['GET'])
def search_users():
    query = request.args.get('query')
    users = User.query.filter((User.firstName.ilike(f'%{query}%')) |
                              (User.lastName.ilike(f'%{query}%')) |
                              (User.email.ilike(f'%{query}%'))).all()
    return users_schema.jsonify(users)

if __name__ == '__main__':
    app.run(debug=True)







