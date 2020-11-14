from datetime import datetime, timedelta
import pytz


def twentyfourhoursfromnow():
    utc=pytz.UTC
    return utc.localize(datetime.now()) + timedelta(1)


def oneweekfromnow():
    utc=pytz.UTC
    return utc.localize(datetime.now()) + timedelta(7)

def yesterday():
    utc=pytz.UTC
    return utc.localize(datetime.now()) + timedelta(-1)

