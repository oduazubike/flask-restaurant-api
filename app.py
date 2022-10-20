import os
import datetime

from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager
from marshmallow import ValidationError
from flask_uploads import configure_uploads

from db import db
from ma import ma
from bc import bcrypt
from resources.vendor_resource import (
    VendorEmailRegister, VendorRegister, TokenRefresh,
    Vendor, Vendors, VendorLogin, ResendEmailConfirmation,
    CriticalLogin, VendorLogoutAccess, VendorLogoutRefresh,
    VendorUpdate, RestaurantNameUpdate)
from resources.confirmation_resource import EmailConfirmations, RecentConfirmation
from resources.password_resource import ForgotPassword, ResetPassword, ChangePassword
from models.blocklist_model import BlocklistModel
from resources.image_resource import LogoUpload, Logo
from libs.image_helper import IMAGE_SET

app = Flask(__name__)


app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PROPAGATE_EXCEPTIONS"] = True
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URI")
app.config["UPLOADED_IMAGES_DEST"] = os.path.join("static", "images")
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(minutes=15)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = datetime.timedelta(days=30)
app.config["JWT_ERROR_MESSAGE_KEY"] = "Message"

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
configure_uploads(app, IMAGE_SET)


api = Api(app)


@app.before_first_request
def create_table():
    db.create_all()


@app.errorhandler(ValidationError)
def handle_marshmallow_validation(err):
    return jsonify(err.messages), 400


jwt = JWTManager(app)


@jwt.token_in_blocklist_loader
def check_for_blocklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = BlocklistModel.find_by_jti(jti)
    return token is not None


@jwt.expired_token_loader
def expired_token(jwt_header, jwt_payload):
    # customising message for expired tokens
    return jsonify({
        "Description": "Your token has expired",
        "Error": "token expired"
    }), 401


@jwt.invalid_token_loader
def invalid_token(error):
    # customising message for invalid tokens
    return jsonify({
        "Description": "This is not a valid jwt token",
        "Error": "Invalid JWT"
    }), 401


@jwt.unauthorized_loader
def unauthorized_json_loader(error):
    # for endpoints that requires a token
    return jsonify({
        "Description": "You need a token to access the endpoint",
        "Error": "Token required endpoint"
    }), 401


@jwt.needs_fresh_token_loader
def require_fresh_token(jwt_header, jwt_payload):
    # customising message for endpoints that requires fresh tokens
    return jsonify({
        "Description":  "This endpoint requires a fresh token",
        "Error": "Fresh token required"
    }), 401


@jwt.revoked_token_loader
def revoked_token(jwt_header, jwt_payload):
    # customising message for logouts or revoked users
    return jsonify({
        "Description": "Your Token has been revoked, You need to login again. ",
        "Error": "Revoked token"
    }), 401


# ________Vendor Resources______ #
api.add_resource(VendorEmailRegister, "/vendor/email")
api.add_resource(VendorRegister, "/vendor/register/<string:confirmation_id>")
api.add_resource(ResendEmailConfirmation, "/vendor/resend_email/<string:email>")
api.add_resource(VendorLogin, "/vendor/login")
api.add_resource(TokenRefresh, "/vendor/refresh")
api.add_resource(CriticalLogin, "/vendor/critical_login")
api.add_resource(VendorLogoutAccess, "/vendor/access_logout")
api.add_resource(VendorLogoutRefresh, "/vendor/refresh_logout")
api.add_resource(Vendor, "/vendor/<int:vendor_id>")
api.add_resource(Vendors, "/vendors")
api.add_resource(EmailConfirmations, "/vendor/confirmations/<int:vendor_id>")
api.add_resource(RecentConfirmation, "/vendor/recent_confirmation/<int:vendor_id>")
api.add_resource(LogoUpload, "/vendor/logo_upload")
api.add_resource(Logo, "/vendor/logo/<int:vendor_id>")
api.add_resource(ForgotPassword, "/vendor/forgot/password")
api.add_resource(ResetPassword, "/vendor/reset/<string:token>")
api.add_resource(ChangePassword, "/vendor/change_password")
api.add_resource(VendorUpdate, "/vendor/update")
api.add_resource(RestaurantNameUpdate, "/vendor/restaurant_update")


if __name__ == "__main__":
    db.init_app(app)
    ma.init_app(app)
    bcrypt.init_app(app)
    app.run(debug=True, port=5000)

