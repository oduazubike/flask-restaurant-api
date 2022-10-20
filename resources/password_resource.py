import datetime
import traceback

from bc import bcrypt
from flask import request, url_for
from flask_restful import Resource
from flask_jwt_extended import (create_access_token, decode_token,
                                get_jwt_identity, jwt_required, get_jwt)

from schemas.vendor_schema import EmailSchema, PasswordSchema, ChangePasswordSchema
from models.vendor_model import VendorModel
from models.blocklist_model import BlocklistModel
from libs.string_getter import gettext
from libs.mailgun import Mailgun, MailGunException
from libs.datetime_helper import datetime_utc_now


forgot_pass_schema = EmailSchema()
password_schema = PasswordSchema()
change_password = ChangePasswordSchema()


class ForgotPassword(Resource):
    @classmethod
    def post(cls):
        """This resource is for requesting a new password reset,
        when password was forgotten."""
        email_json = request.get_json()
        data = forgot_pass_schema.load(email_json)

        vendor = VendorModel.find_by_email(data.email)
        if not vendor:
            return {"Message": gettext("ven_not_found")}, 404

        try:
            expires = datetime.timedelta(minutes=5)
            # creates and expiration time
            token = create_access_token(identity=vendor.id, fresh=False,
                                        expires_delta=expires)
            url = request.url_root[:-1] + url_for("resetpassword", token=token)
            # to strip last character from the request.url_root(127.0.0.1:5000/)
            # because the url_for starts with a slash(/)
            subject = "Reset Password"
            text = f"Click the link to Reset your Password: {url}\n" \
                f"Copy this token <{token}>\n" \
                f"And use as token in the Reset Password Resource"

            Mailgun.send_email(email=vendor.email, subject=subject, text=text)
            # creates email object and sends email
            return {"Message": gettext("ven_reset_password_email_sent")}, 200
        except MailGunException as e:
            return {"message": str(e)}, 500
        except:
            traceback.print_exc()
            return {"message": gettext("ven_internal_error")}, 500


class ResetPassword(Resource):
    @classmethod
    def put(cls, token: str):
        """Resource for resetting the password after a forgot request.
        Takes the token as path param. It also revokes the token"""
        password_json = request.get_json()
        data = password_schema.load(password_json)

        vendor_id = decode_token(token)["sub"]
        # decodes the token(decodes because it is not passed in the Authorization header)
        # And extracts the identity of the token
        vendor = VendorModel.find_by_id(vendor_id)
        # finds Vendor with the extracted identity

        if not vendor:
            return {"Message": gettext("ven_not_found")}, 404

        try:
            hashed_pw = bcrypt.generate_password_hash(data.password).decode('utf-8')
            # hashes password and decodes to string
            vendor.password = hashed_pw
            # sets password column in db to new hashed password
            vendor.save_to_database()

            # After successfully changing the password, we revoke the token used
            # to ensure it is not re-used for this operation and login operations
            jwt = decode_token(token)  # decodes toke again for revoking
            jti = jwt["jti"]
            ttype = jwt["type"]
            token = BlocklistModel(jti=jti, owner=vendor.email, type=ttype,
                                   created_at=datetime_utc_now())
            token.save_to_db()

            return {"Message": gettext("ven_password_reset")}, 200
        except:
            traceback.print_exc()
            return {"message": gettext("ven_internal_error")}, 500


class ChangePassword(Resource):
    @classmethod
    @jwt_required(fresh=True)
    def put(cls):
        """Resource changes password for logged-in vendor and
        revokes the token so the vendor has to login with the new password"""
        password_json = request.get_json()
        pass_data = change_password.load(password_json)

        identity = get_jwt_identity()
        vendor = VendorModel.find_by_id(identity)

        if vendor and bcrypt.check_password_hash(vendor.password, pass_data["password"]):
            try:
                hashed_pw = bcrypt.generate_password_hash(pass_data["new_password"]).decode('utf-8')
                # we index the schema variable here because this schema is not looking at the database,
                # they are just marshmallow fields and not SQLAlchemy fields
                vendor.password = hashed_pw
                vendor.save_to_database()

                # we also revoke the token, because they need to log-in again after a change of password
                jwt = get_jwt()
                jti = jwt["jti"]
                ttype = jwt["type"]
                token = BlocklistModel(jti=jti, owner=vendor.email, type=ttype,
                                       created_at=datetime_utc_now())
                token.save_to_db()

                return {"Message": gettext("ven_password_changed")}, 200
            except:
                traceback.print_exc()
                return {"message": gettext("ven_internal_error")}, 500
        return {"Message": gettext("ven_incorrect_password")}, 401


