from flask import request, url_for

from db import db
from libs.mailgun import Mailgun
from models.confirmation_model import VendorEmailModel


class VendorModel(db.Model):
    __tablename__ = "vendors"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    full_name = db.Column(db.String(80))
    dob = db.Column(db.String)
    restaurant = db.Column(db.String(80), unique=True)
    city = db.Column(db.String(80))
    date_created = db.Column(db.String, nullable=False)
    validated = db.Column(db.Boolean, default=False)

    confirmation = db.relationship(
        "VendorEmailModel", lazy="dynamic",
        cascade="all, delete-orphan", overlaps="vendor"
    )

    def __repr__(self):
        return f"<Restaurant: {self.email} ! {self.dob}>"

    @classmethod
    def find_by_id(cls, _id: int) -> "VendorModel":
        return cls.query.filter_by(id=_id).first()

    @classmethod
    def find_by_email(cls, email: str) -> "VendorModel":
        return cls.query.filter_by(email=email).first()

    @classmethod
    def find_by_restaurant(cls, restaurant: str) -> "VendorModel":
        return cls.query.filter_by(restaurant=restaurant).first()

    @classmethod
    def find_all(cls) -> ["VendorModel"]:
        return cls.query.all()

    def send_confirmation_email(self):
        subject = "Registration Confirmation"
        link = request.url_root[:-1] + url_for(
            "vendorregister", confirmation_id=VendorEmailModel.most_recent_confirmation().id)
        text = f"Please click the link to confirm your registration: {link}\n" \
            f"Copy this ID <{VendorEmailModel.most_recent_confirmation().id}> \n" \
            f"And use as confirmation id in the Register Resource"
        # html = f"<html>Please click the link to confirm your registration: <a href={link}>link</a></html>"
        return Mailgun.send_email([self.email], subject, text)

    def save_to_database(self) -> None:
        db.session.add(self)
        db.session.commit()

    def delete_from_database(self) -> None:
        db.session.delete(self)
        db.session.commit()

    @staticmethod
    def commit_change() -> None:
        db.session.commit()

    @staticmethod
    def rollback_change() -> None:
        db.session.rollback()

# static methods because they do not take an argument
