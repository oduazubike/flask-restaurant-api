import traceback

from flask import request
from flask_restful import Resource
from flask_jwt_extended import (create_refresh_token, create_access_token,
                                jwt_required, get_jwt_identity, get_jwt)
from sqlalchemy.exc import IntegrityError

from bc import bcrypt
from models.vendor_model import VendorModel
from models.confirmation_model import VendorEmailModel
from models.blocklist_model import BlocklistModel
from schemas.vendor_schema import VendorEmailSchema, VendorSchema, PasswordSchema
from libs.datetime_helper import datetime_utc_now
from libs.string_getter import gettext
from libs.mailgun import MailGunException

email_schema = VendorEmailSchema()
vendor_schema = VendorSchema()
all_vendor_schema = VendorSchema(many=True)
critical_schema = PasswordSchema()


class VendorEmailRegister(Resource):
    @classmethod
    def post(cls):
        """To send confirmation email to applying vendors,
        link sent to email to redirect  vendor to registration
        page for inputting other details"""
        vendor_json = request.get_json()
        data = email_schema.load(vendor_json)

        if VendorModel.find_by_email(data.email):
            return {"Message": gettext("ven_email_already_exists").format(data.email)}, 400

        hashed_pw = bcrypt.generate_password_hash(data.password).decode('utf-8')
        vendor = VendorModel(email=data.email, password=hashed_pw,
                             date_created=datetime_utc_now())
        # creates an object of the VendorModel
        try:
            vendor.save_to_database()
            confirmation = VendorEmailModel(vendor.id)
            # creates confirmation obj, passes the vendor's id as the confirmation
            # ForeignKey to map that vendor to that confirmation obj
            confirmation.save_to_database()
            vendor.send_confirmation_email()
            return {"Message": gettext("ven_email_sent").format(vendor.email)}, 200
        except MailGunException as e:
            vendor.delete_from_database()
            return {"message": str(e)}, 500
        except:
            vendor.delete_from_database()
            traceback.print_exc()
            return {"Message": gettext("ven_internal_error")}, 500


class ResendEmailConfirmation(Resource):
    @classmethod
    def post(cls, email: str):
        """Resends confirmation email, if not validated and if email already registered"""
        vendor = VendorModel.find_by_email(email)

        if not vendor:
            return {"Message": gettext("ven_not_found")}, 404

        if vendor.validated:
            return {"Message": gettext("ven_email_already_validated").format(vendor.email)}, 400

        try:
            confirmation = VendorEmailModel(vendor.id)
            recent_confirm = confirmation.most_recent_confirmation()
            if recent_confirm:
                recent_confirm.force_to_expire()

            new_confirmation = VendorEmailModel(vendor.id)
            new_confirmation.save_to_database()
            vendor.send_confirmation_email()
            return {"Message": gettext("confirm_resend_successful").format(vendor.email)}, 200
        except MailGunException as e:
            return {"message": str(e)}, 500
        except:
            traceback.print_exc()
            return {"message": gettext("confirm_resend_fail")}, 500


class VendorRegister(Resource):
    @classmethod
    def put(cls, confirmation_id: str):
        """Completes a Vendor's Registration...
        Using the confirmation id(a string) sent to the email as the path param"""
        vendor_json = request.get_json()
        confirmation = VendorEmailModel.find_by_id(confirmation_id)
        if not confirmation:
            return {"Message": gettext("confirm_not_found")}, 404

        if confirmation.expired:
            return {"Message": gettext("confirm_link_expired")}, 400

        vendor = VendorModel.find_by_id(confirmation.vendor_id)
        # finds the vendor with that ForeignKey and creates obj of that vendor.

        # Vendor object is created below those two checks, to make sure confirmation was found and not
        # expired before searching for the user with the ForeignKey, hence preventing AttributeError

        vendor.full_name = vendor_json["full_name"]
        vendor.dob = vendor_json["dob"]
        vendor.restaurant = vendor_json["restaurant"]
        vendor.city = vendor_json["city"]
        vendor_schema.load(vendor_json)

        if vendor.validated:
            return {"Message": gettext("ven_confirm_link_used").format(vendor.email)}, 400

        try:
            vendor.commit_change()
            vendor.validated = True
            # validates vendors on successful submission of details
            vendor.date_created = datetime_utc_now()  # resets time to this time of submission
            vendor.commit_change()
            return {"Message": gettext("ven_restaurant_created").format(vendor.restaurant)}, 201
        except IntegrityError:
            # catches SQLAlchemy IntegrityError because vendor.restaurant is unique=True
            return {"Message": gettext("ven_restaurant_exists").format(vendor_json["restaurant"])}, 400
        except:
            vendor.rollback_change()
            traceback.print_exc()
            return {"Message": gettext("ven_internal_error")}, 500


class VendorLogin(Resource):
    @classmethod
    def post(cls):
        vendor_json = request.get_json()
        vendor_data = email_schema.load(vendor_json)

        vendor = VendorModel.find_by_email(vendor_data.email)

        if vendor and bcrypt.check_password_hash(vendor.password, vendor_data.password):
            if vendor.validated:
                access_token = create_access_token(identity=vendor.id, fresh=True)
                refresh_token = create_refresh_token(vendor.id)

                return {"access_token": access_token, "refresh_token": refresh_token}, 200
            return {"Message": gettext("ven_unvalidated")}, 400
        return {"Message": gettext("ven_invalid_credentials")}, 401


class CriticalLogin(Resource):
    """Returns fresh access_token to allow
    access to critical operation. This Resource should be called
    with a correct password for any resource that
    requests a fresh token"""
    @classmethod
    @jwt_required(refresh=True)
    def post(cls):
        vendor_json = request.get_json()
        vendor_data = critical_schema.load(vendor_json)

        vendor_id = get_jwt_identity()
        vendor = VendorModel.find_by_id(vendor_id)

        if vendor and bcrypt.check_password_hash(vendor.password, vendor_data.password):
            access_token = create_access_token(identity=vendor.id, fresh=True)

            return {"access_token": access_token}, 200
        return {"Message": gettext("ven_invalid_credentials")}, 401


class TokenRefresh(Resource):
    @classmethod
    @jwt_required(refresh=True)
    def post(cls):
        vendor_id = get_jwt_identity()
        new_access_token = create_access_token(identity=vendor_id, fresh=False)

        return {"access_token": new_access_token}, 200


class VendorLogoutAccess(Resource):
    @classmethod
    @jwt_required()
    def post(cls):
        """Logs a vendor's access token out and keeps track
        of who logged out. This resource and the refresh_logout
        must be called for a successful logout"""
        identity = get_jwt_identity()
        owner = VendorModel.find_by_id(identity)

        jwt = get_jwt()
        jti = jwt["jti"]
        ttype = jwt["type"]
        token = BlocklistModel(jti=jti, owner=owner.email, type=ttype,
                               created_at=datetime_utc_now())
        token.save_to_db()

        return {"message": gettext("ven_logout_successful").format(ttype)}, 200


class VendorLogoutRefresh(Resource):
    @classmethod
    @jwt_required(refresh=True)
    def post(cls):
        """Logs a vendor's refresh token out and keeps track
        of who logged out This resource and the access_logout
        must be called for a successful logout"""
        identity = get_jwt_identity()
        owner = VendorModel.find_by_id(identity)

        jwt = get_jwt()
        jti = jwt["jti"]
        ttype = jwt["type"]
        token = BlocklistModel(jti=jti, owner=owner.email, type=ttype,
                               created_at=datetime_utc_now())
        token.save_to_db()

        return {"message": gettext("ven_logout_successful").format(ttype)}, 200


class Vendor(Resource):
    @classmethod
    def get(cls, vendor_id: int):
        """retrieves a vendor's full details"""
        vendor = VendorModel.find_by_id(vendor_id)
        if not vendor:
            return {"message": gettext("ven_not_found")}, 404
        return vendor_schema.dump(vendor), 200

    @classmethod
    @jwt_required(fresh=True)
    def delete(cls, vendor_id: int):
        """Deletes a vendor from the database, privilege
        limited only the vendor that owns the account"""
        identity = get_jwt_identity()

        vendor = VendorModel.find_by_id(vendor_id)
        if not vendor:
            return {"Message": gettext("ven_not_found")}, 404

        if identity != vendor_id:
            return {"Message": gettext("ven_not_privileged")}, 403

        vendor.delete_from_database()
        return {"Message": gettext("ven_deleted")}, 200


class Vendors(Resource):
    @classmethod
    def get(cls):
        return {"Vendors": all_vendor_schema.dump(VendorModel.find_all())}, 200


# Implement the vendor resource to display a few vendor info and all items it has.

