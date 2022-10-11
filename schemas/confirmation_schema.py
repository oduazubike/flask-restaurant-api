from ma import ma
from models.confirmation_model import VendorEmailModel


class VendorEmailSchema(ma.SQLAlchemyAutoSchema):

    class Meta:
        model = VendorEmailModel
        load_instance = True
        dump_only = ("id", "expire_at", "vendor_id")
        load_only = ("vendor",)
        include_fk = True
