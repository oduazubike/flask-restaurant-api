import time

from flask_restful import Resource

from models.confirmation_model import VendorEmailModel
from schemas.confirmation_schema import VendorEmailSchema
from models.vendor_model import VendorModel
from libs.string_getter import gettext

confirmation_schema = VendorEmailSchema()


class RecentConfirmation(Resource):
    @classmethod
    def get(cls, vendor_id):
        """Gets the most recent confirmation of a vendor, for testing purposes"""
        vendor = VendorModel.find_by_id(vendor_id)
        if not vendor:
            return {"Message": gettext("ven_not_found")}, 404

        confirmation = VendorEmailModel.most_recent_confirmation()
        return confirmation_schema.dump(confirmation)


class EmailConfirmations(Resource):
    @classmethod
    def get(cls, vendor_id):
        """Displays all confirmations created for a particular vendor"""
        vendor = VendorModel.find_by_id(vendor_id)
        if not vendor:
            return {"Message": gettext("ven_not_found")}, 404

        return ({
            "Current-Time": int(time.time()),
            "Confirmations": [
                confirmation_schema.dump(each)
                for each in vendor.confirmation.order_by(VendorEmailModel.expire_at)
            ]
        }), 200
