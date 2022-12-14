from marshmallow import Schema, fields
from werkzeug.datastructures import FileStorage


class FileStorageField(fields.Field):
    make_error = {
        "invalid": "Not a valid Image"
    }

    def _deserialize(self, value, attr, data, **kwargs):

        if value is None:
            return None

        if not isinstance(value, FileStorage):
            self.fail("invalid")

        return value


class ImageSchema(Schema):
    image = FileStorageField(required=True)
