import json

default_locale = "english"
cached_strings = {}


def refresh():
    global cached_strings
    with open(f"strings/{default_locale}.json") as file:
        cached_strings = json.load(file)


def gettext(name):
    return cached_strings[name]


def reset_locale(locale):
    global default_locale
    default_locale = locale


refresh()

