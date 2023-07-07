
from flask import Flask, g, make_response, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
import os
from datetime import datetime as dt, timedelta
import secrets
from werkzeug.security import generate_password_hash, check_password_hash


class Config:
    SQLALCHEMY_DATABASE_URI=os.environ.get('SQLALCHEMY_DATABASE_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS=os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')


app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app,db)
cors = CORS(app)

basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth()

@basic_auth.verify_password
def verify_password(email, password):
    u = db.session.execute(db.select(User).where((User.email==email))).scalars().first()
    if u is None:
        return False
    g.current_user = u
    return u.check_hashed_password(password)

@token_auth.verify_token
def verify_token(token):
    u = User.check_token(token) if token else None
    g.current_user = u
    return g.current_user or None


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, index=True, unique=True)
    first_name = db.Column(db.String)
    last_name = db.Column(db.String)
    password = db.Column(db.String)
    created_on = db.Column(db.DateTime, default=dt.utcnow)
    modified_on = db.Column(db.DateTime, onupdate=dt.utcnow)
    token = db.Column(db.String, index=True, unique=True)
    token_exp = db.Column(db.DateTime)
    # cart = db.relationship('Cart', backref="cart", lazy="dynamic", cascade="all, delete-orphan" )

    def get_token(self, exp=86400):
        current_time = dt.utcnow()
        if self.token and self.token_exp > current_time + timedelta(seconds=60):
            return self.token
        self.token = secrets.token_urlsafe(32)
        self.token_exp = current_time + timedelta(seconds=exp)
        self.save()
        return self.token

    def revoke_token(self):
        self.token_exp = dt.utcnow() - timedelta(seconds = 120)

    @staticmethod
    def check_token(token):
        u = db.session.execute(db.select(User).where((User.token==token))).scalars().first()
        if not u or u.token_exp < dt.utcnow():
            return None
        return u

    def hash_password(self, original_password):
        return generate_password_hash(original_password)
    
    def check_hashed_password(self, login_password):
        return check_password_hash(self.password, login_password)

    def __repr__(self):
        return f'<{self.id} | {self.email}>'

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def to_dict(self):
        return{
            "id":self.id,
            "email":self.email,
            "first_name":self.first_name,
            "last_name":self.last_name,
            "created_on":self.created_on,
            "modified_on":self.modified_on,
            "token":self.token,
        }

    def from_dict(self, data):
        for field in ["email", "first_name", "last_name", "password"]:
            if field in data:
                if field == "password":
                    setattr(self, field, self.hash_password(data[field]))
                else:
                    setattr(self, field, data[field])




@app.get('/user')
@basic_auth.login_required()
def login():
    g.current_user.get_token()
    return make_response(g.current_user.to_dict(), 200)

@app.post('/user')
def register():
    data = request.get_json()
    old_user = db.session.execute(db.select(User).where((User.email==data.get('email')))).scalars().first()
    if old_user:
        abort(422)
    new_user = User()
    new_user.from_dict(data)
    new_user.save()
    return make_response("success", 200)

@app.put('/user')
@token_auth.login_required()
def edit_user():
    data = request.get_json()
    if data.get('email'):
        old_user = db.session.execute(db.select(User).where((User.email==data.get('email')))).scalars().first()
        if old_user:
            if old_user.id != g.current_user.id:
                abort(422) 
    g.current_user.from_dict(data)
    g.current_user.save()
    return make_response("success",200)

@app.delete('/user')
@token_auth.login_required()
def delete_user():
    g.current_user.delete()
    return make_response("success",200)


class Meniu(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    title=db.Column(db.String)
    price=db.Column(db.Float)
    image=db.Column(db.String(120))


class Cart(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    quantity = db.Column(db.Integer)
    meniu_id = db.Column(db.Integer, db.ForeignKey('meniu.id'))

