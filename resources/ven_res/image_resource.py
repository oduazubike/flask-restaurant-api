import os
import traceback

from flask_restful import Resource
from flask import request, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity

from schemas.image_schema import ImageSchema
from libs.string_getter import gettext
from libs import image_helper

image_schema = ImageSchema()


class LogoUpload(Resource):
    @classmethod
    @jwt_required()
    def put(cls):
        """Uploads the Vendor's Logo image:
        First checks if the file to be uploaded is supported. If supported,
        we'll delete the existing one, as there must only be one logo at a time."""
        data = image_schema.load(request.files)
        vendor_id = get_jwt_identity()
        filename = f"vendor_{vendor_id}"
        folder = "vendor_logos"

        if image_helper.ext_checker(image_helper.get_extension(data["image"])):
            # checks if the file extension is in ALLOWED_EXT(variable in image_helper)
            ext = image_helper.get_extension(data["image"])
            return {"Message": gettext("img_extension_not_allowed").format(ext)}, 400

        logo_path = image_helper.find_by_extension(filename=filename, folder=folder)
        if logo_path:
            try:
                os.remove(logo_path)
            except:
                return {"Message": gettext("img_failed_to_delete")}, 500
        try:
            extension = image_helper.get_extension(data["image"].filename)
            logo_image = filename + extension
            path = image_helper.save_image(data["image"], folder=folder, name=logo_image)
            basename = image_helper.get_basename(path)
            return {"message": gettext("img_uploaded").format(basename)}, 200
        except:
            return {"Message": gettext("img_internal_error")}, 500


class Logo(Resource):
    @classmethod
    @jwt_required()
    def get(cls, vendor_id):
        folder = "vendor_logos"
        filename = f"vendor_{vendor_id}"

        logo_path = image_helper.find_by_extension(filename, folder)
        if logo_path:
            return send_file(logo_path)
        return {"Message": gettext("img_not_found")}, 404

    @classmethod
    @jwt_required()
    def delete(cls, vendor_id: int):
        """Checks if vendor is the account owner, if not
        delete will not be authorized"""
        identity = get_jwt_identity()

        folder = "vendor_logos"
        filename = f"vendor_{vendor_id}"

        logo_path = image_helper.find_by_extension(filename, folder)
        if not logo_path:
            return {"Message": gettext("img_not_found")}, 404

        if identity != vendor_id:
            return {"Message": gettext("ven_not_privileged")}, 403

        try:
            os.remove(logo_path)
            return {"Message": gettext("img_deleted")}, 200
        except:
            traceback.print_exc()
            return {"Message": gettext("img_failed_to_delete")}, 500

