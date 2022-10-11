from db import db


class BlocklistModel(db.Model):
    __tablename__ = "blocklists"

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(70), nullable=False, index=True)
    type = db.Column(db.String(16), nullable=False)
    owner = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    # index=True for jti because: index is for performance of queries.
    # A SQL index is a quick lookup table for finding records users need to search frequently

    @classmethod
    def find_by_jti(cls, jti: str) -> "BlocklistModel":
        return cls.query.filter_by(jti=jti).scalar()
    # Scalar() Return the first element of the first result or None if no rows present.
    # If multiple rows are returned, raises MultipleResultsFound.

    def save_to_db(self) -> None:
        db.session.add(self)
        db.session.commit()
