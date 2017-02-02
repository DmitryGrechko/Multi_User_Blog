class DateValidation:

    def __init__(self):
        pass


def valid_month(month):
    month_abbvs = dict((m[:3].lower(), m) for m in months)
    if month:
        short_month = month[:3].lower()
        return month_abbvs.get(short_month)


def valid_day(day):
    if day.isdigit() is True:
        day = int(day)
        if day > 0 and day <= 31:
            return day


def valid_year(year):
    if year.isdigit() is True:
        year = int(year)
        if year >= 1900 and year <= 2020:
            return year

months = ['January',
          'February',
          'March',
          'April',
          'May',
          'June',
          'July',
          'August',
          'September',
          'October',
          'November',
          'December']
