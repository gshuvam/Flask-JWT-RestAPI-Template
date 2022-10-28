from email.policy import default
from enum import unique
from sqlite3 import dbapi2
from package import db

class User(db.Model):
    id = db.Column(db.String(30), unique=True, primary_key=True)
    email = db.Column(db.String(30), unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self) -> str:
        return f"User({self.name}, {self.email}, {self.admin})"
    