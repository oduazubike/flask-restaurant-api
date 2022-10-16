import os
import traceback
import datetime

from flask import request
from flask_restful import Resource
from flask_jwt_extended import (create_refresh_token, create_access_token,
                                jwt_required, get_jwt_identity, get_jwt)
from sqlalchemy.exc import IntegrityError

from bc import bcrypt
from models.vendor_model import VendorModel
from models.confirmation_model import VendorEmailModel
from models.blocklist_model import BlocklistModel
from schemas.vendor_schema import (VendorEmailSchema,
                                   VendorUpdateSchema, VendorSchema,
                                   PasswordSchema, RestaurantNameSchema)
from libs.datetime_helper import datetime_utc_now
from libs.string_getter import gettext
from libs.mailgun import MailGunException
from libs import image_helper

email_schema = VendorEmailSchema()
vendor_schema = VendorSchema()
all_vendor_schema = VendorSchema(many=True)
critical_schema = PasswordSchema()
update_schema = VendorUpdateSchema()
restaurant_schema = RestaurantNameSchema()


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
        # hashes password and decodes to string
        vendor = VendorModel(email=data.email, password=hashed_pw,
                             date_created=datetime_utc_now(),
                             res_last_updated=datetime.datetime.now())
        # creates an object of the VendorModel
        try:
            vendor.save_to_database()
            confirmation = VendorEmailModel(vendor.id)
            # creates confirmation obj, passes the vendor's id as the confirmation's
            # ForeignKey to map that vendor to that confirmation obj
            confirmation.save_to_database()  # saves to db
            vendor.send_confirmation_email()  # and sends to email
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
            # First finds confirmation objects that already exists
            # by: creating confirmation obj
            # return the most recent
            # then expiring it if it isn't expired
            confirmation = VendorEmailModel(vendor.id)  # creates confirmation obj with Vendor's ID
            recent_confirm = confirmation.most_recent_confirmation()  # method returns the most recent confirmation ID
            if recent_confirm:
                recent_confirm.force_to_expire()
                # if a recent confirmation exists and not yet expired, expire it

            new_confirmation = VendorEmailModel(vendor.id)  # creates a new confirmation obj
            new_confirmation.save_to_database()  # save to db
            vendor.send_confirmation_email()  # and send in email
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
        vendor_schema.load(vendor_json)

        confirmation = VendorEmailModel.find_by_id(confirmation_id)
        if not confirmation:
            return {"Message": gettext("confirm_not_found")}, 404

        if confirmation.expired:
            return {"Message": gettext("confirm_link_expired")}, 400

        vendor = VendorModel.find_by_id(confirmation.vendor_id)
        # finds the vendor with that ForeignKey and creates obj of that vendor.

        # Vendor object is created below those two checks, to make sure confirmation was found and not
        # expired before searching for the Vendor with the ForeignKey, thus preventing AttributeError

        vendor.full_name = vendor_json["full_name"]
        vendor.dob = vendor_json["dob"]
        vendor.restaurant = vendor_json["restaurant"]
        vendor.city = vendor_json["city"]
        # these columns are null at this point, we receive these details and add to the null columns

        if vendor.validated:
            return {"Message": gettext("ven_confirm_link_used").format(vendor.email)}, 400

        try:
            vendor.save_to_database()
            vendor.validated = True
            # validates vendors on successful submission of details
            vendor.date_created = datetime_utc_now()  # resets time to this time of submission
            vendor.save_to_database()
            return {"Message": gettext("ven_restaurant_created").format(vendor.restaurant)}, 201
        except IntegrityError:
            # catches SQLAlchemy IntegrityError because vendor.restaurant is unique=True
            return {"Message": gettext("ven_restaurant_exists").format(vendor_json["restaurant"])}, 400
        except:
            vendor.rollback_change()
            # to rollback if an internal error occurs
            traceback.print_exc()
            return {"Message": gettext("ven_internal_error")}, 500


class VendorLogin(Resource):
    @classmethod
    def post(cls):
        """Login Resource, returns access and refresh token if Vendor exists
        and details are entered correctly"""
        vendor_json = request.get_json()
        vendor_data = email_schema.load(vendor_json)

        vendor = VendorModel.find_by_email(vendor_data.email)

        if vendor and bcrypt.check_password_hash(vendor.password, vendor_data.password):
            # if vendor exists and compares supplied password to hashed password in the database
            if vendor.validated:
                # if the vendor have been register or validated
                access_token = create_access_token(identity=vendor.id, fresh=True)
                refresh_token = create_refresh_token(vendor.id)

                return {"access_token": access_token, "refresh_token": refresh_token}, 200
            return {"Message": gettext("ven_unvalidated")}, 400
        return {"Message": gettext("ven_invalid_credentials")}, 401


class CriticalLogin(Resource):
    """Returns fresh access_token to allow
    access to critical operation. This Resource should be called
    (instead of having to login again)
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
        """Resource to refresh a Vendor's token before or when it expires.
        Requires a refresh token, and return a non-fresh token"""
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
        # gets the jwt token, returning a dictionary of the token
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
        # gets the jwt token, returning a dictionary of the token
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
        limited only the vendor that owns the account and admin"""
        identity = get_jwt_identity()

        folder = "vendor_logos"
        filename = f"vendor_{vendor_id}"

        vendor = VendorModel.find_by_id(vendor_id)
        if not vendor:
            return {"Message": gettext("ven_not_found")}, 404

        if identity != vendor_id:
            return {"Message": gettext("ven_not_privileged")}, 403

        try:
            # deletes the vendor's image alongside
            logo_path = image_helper.find_by_extension(filename, folder)
            if logo_path is not None:  # if the path exists
                os.remove(logo_path)
            vendor.delete_from_database()
            return {"Message": gettext("ven_deleted")}, 200
        except:
            traceback.print_exc()
            return {"Message": gettext("ven_internal_error")}, 500


class Vendors(Resource):
    @classmethod
    def get(cls):
        return {"Vendors": all_vendor_schema.dump(VendorModel.find_all())}, 200


class VendorUpdate(Resource):
    @classmethod
    @jwt_required()
    def put(cls):
        """Resource to update other(less critical) details of vendor account.
        Updates account for logged-in vendor."""
        vendor_json = request.get_json()
        update_schema.load(vendor_json)

        vendor_id = get_jwt_identity()
        vendor = VendorModel.find_by_id(vendor_id)

        if not vendor_json["full_name"]:
            vendor_json["full_name"] = vendor.full_name
        if not vendor_json["dob"]:
            vendor_json["dob"] = vendor.dob
        if not vendor_json["city"]:
            vendor_json["city"] = vendor.city
        # if no values is passed for any of the fields, then we set the fields to the value in the database

        vendor.full_name = vendor_json["full_name"]
        vendor.dob = vendor_json["dob"]
        vendor.city = vendor_json["city"]
        # else we use the value they passed
        vendor.save_to_database()

        return vendor_schema.dump(vendor), 200


class RestaurantNameUpdate(Resource):
    @classmethod
    @jwt_required(fresh=True)
    def put(cls):
        """Resource to change restaurant name for vendor's account.
        Updates restaurant name for logged-in vendor's account.
        And accepts only fresh access tokens"""
        vendor_json = request.get_json()
        restaurant_schema.load(vendor_json)

        vendor_id = get_jwt_identity()
        vendor = VendorModel.find_by_id(vendor_id)

        update_time = datetime.timedelta(days=30)
        time_delta = vendor.res_last_updated + update_time
        # adds 30 days to present date of vendor.res_last_updated
        valid_update = datetime.datetime.now() > time_delta
        # boolean, to check if present date is more than 30days after last update

        try:
            if valid_update:
                if not vendor_json["restaurant"]:
                    # if no value is passed to "restaurant"
                    vendor_json["restaurant"] = vendor.restaurant
                    # then we set "restaurant" to the value in the database
                vendor.restaurant = vendor_json["restaurant"]
                vendor.res_last_updated = datetime.datetime.now()
                # updates the vendor.res_last_updated to present date
                vendor.save_to_database()
                return vendor_schema.dump(vendor), 200
            return {"Message": gettext("ven_restaurant_name_update_time_not_reached")}, 400
        except IntegrityError:
            # catches IntegrityError because restaurant does not allow duplicate name
            return {"Message": gettext("ven_restaurant_exists").format(vendor_json["restaurant"])}, 400


# Implement the vendor resource to display a few vendor info and all items it has.

