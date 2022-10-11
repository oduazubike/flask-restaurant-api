import os
from typing import Union

from werkzeug.datastructures import FileStorage
from flask_uploads import UploadSet, IMAGES


ALLOWED_EXT = ['.jpg', '.jpe', '.jpeg', '.png', '.gif', '.svg', '.bmp']

IMAGE_SET = UploadSet("images", IMAGES)


def save_image(image: FileStorage, folder: str = None, name: str = None) -> str:
    """saves image to this folder, if name is not passed,
    it makes use of the image name(from the user file) as the name"""
    return IMAGE_SET.save(image, folder, name)


def find_by_extension(filename: str, folder: str) -> Union[str, None]:
    for ext in IMAGES:
        image_name = f"{filename}.{ext}"
        image_path = IMAGE_SET.path(filename=image_name, folder=folder)
        # creates the full path fo the image
        if os.path.isfile(image_path):
            return image_path
    return None


def ext_checker(ext) -> bool:
    """checks if the extension passed
    is not in ALLOWED_EXT"""
    if ext not in ALLOWED_EXT:
        return True


def _retrieve_filename(file: Union[str, FileStorage]) -> str:
    """takes a FileStorage and returns the filename(return a string) OR
    takes the file(a string) and returns the filename(a string)"""
    if isinstance(file, FileStorage):
        return file.filename
    return file  # return the  string


def get_basename(file: Union[str, FileStorage]) -> str:
    """returns fullname of image from the path"""
    filename = _retrieve_filename(file)
    return os.path.split(filename)[1]


def get_extension(file: Union[str, FileStorage]) -> str:
    """splits file path get file extension"""
    filename = _retrieve_filename(file)
    return os.path.splitext(filename)[1]
