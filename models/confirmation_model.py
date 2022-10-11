from time import time
from uuid import uuid4

from db import db

EXPIRES_DELTA = 1800


class VendorEmailModel(db.Model):
    __tablename__ = "email_confirmations"

    id = db.Column(db.String(50), primary_key=True)
    expire_at = db.Column(db.Integer, nullable=False)
    vendor_id = db.Column(db.Integer, db.ForeignKey("vendors.id"), nullable=False)
    vendor = db.relationship("VendorModel")

    def __init__(self, vendor_id: int, **kwargs):
        super().__init__(**kwargs)
        self.id = uuid4().hex
        self.vendor_id = vendor_id
        self.expire_at = int(time()) + EXPIRES_DELTA
        # time() is a float by default, we convert to integer instead

    @classmethod
    def find_by_id(cls, _id: str) -> "VendorEmailModel":
        return cls.query.filter_by(id=_id).first()

    @property
    def expired(self) -> bool:
        return time() > self.expire_at
    # if present time is greater that expiration time(expire_at) that is if 3min after

    @classmethod
    def most_recent_confirmation(cls) -> "VendorEmailModel":
        return cls.query.order_by(db.desc(cls.expire_at)).first()

    def force_to_expire(self) -> None:
        if not self.expired:
            self.expire_at = int(time())
            self.save_to_database()
            # if not expired, change time to present, and save to database

    def save_to_database(self) -> None:
        db.session.add(self)
        db.session.commit()

    def delete_from_database(self) -> None:
        db.session.delete(self)
        db.session.commit()
