from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field
from marshmallow import Schema, fields

from db import db
from models.vendor_model import VendorModel


class VendorEmailSchema(SQLAlchemySchema):
    """Schema for registering and confirming a vendor's email"""
    class Meta:
        model = VendorModel
        load_instance = True
        sqla_session = db.session

    email = auto_field()
    password = auto_field()
    # nullable=False fields, need not be required here


class VendorSchema(SQLAlchemySchema):
    """Schema for complete registration of a vendor,
    with complete details. Comes immediately after registering
    the vendor's email"""
    class Meta:
        model = VendorModel
        load_instance = True
        sqla_session = db.session

    id = auto_field(dump_only=True)
    email = auto_field(dump_only=True)
    full_name = auto_field(required=True)
    dob = auto_field(required=True)
    restaurant = auto_field(required=True)
    city = auto_field(required=True)
    date_created = auto_field(dump_only=True)
    validated = auto_field(dump_only=True)


class VendorUpdateSchema(SQLAlchemySchema):
    """Schema for update of vendor account details"""
    class Meta:
        model = VendorModel
        load_instance = True
        sqla_session = db.session

    full_name = auto_field()
    dob = auto_field()
    city = auto_field()


class PasswordSchema(SQLAlchemySchema):
    """Schema for password only entries: CriticalLogin and ResetPassword"""
    class Meta:
        model = VendorModel
        load_instance = True
        sqla_session = db.session

    password = auto_field(required=True)


class EmailSchema(SQLAlchemySchema):
    """Schema for email only entries: ForgotPassword"""
    class Meta:
        model = VendorModel
        load_instance = True
        sqla_session = db.session

    email = auto_field(required=True)


class ChangePasswordSchema(Schema):
    """Schema for manually changing passwords:
    This doesn't connect with the database, hence we inherit Schema."""
    password = fields.Str(required=True)
    new_password = fields.Str(required=True)
