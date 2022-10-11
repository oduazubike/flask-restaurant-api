import datetime
import pytz


def datetime_utc_now():
    utc_now = datetime.datetime.now(tz=pytz.UTC)
    return utc_now
