from datetime import datetime, timedelta


def twentyfourhoursfromnow():
    return datetime.now() + timedelta(1)


def oneweekfromnow():
    return datetime.now() + timedelta(7)
