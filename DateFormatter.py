#Translating DateFormatter.java from CICFlowMeter package
from datetime import datetime, timezone
from dateformat import DateFormat
from tzlocal import get_localzone

class DateFormatter:
    def parseDateFromLong(self, time, format):
        try:
            if (format == null):
                format = "dd/MM/yyyy hh:mm:ss"
            simpleFormatter = DateFormat(format)
            tempDate = datetime.datetime.fromtimestamp(time)
            return tempDate.strftime(simpleFormatter)
        except:
            print("An exception occurred")##what is exception ex in .java ?
            return "dd/MM/yyyy hh:mm:ss"

    def converMilliseconds2String(self, time, format):
        if (format == null):
            format = "dd/MM/yyyy hh:mm:ss"
        formatter = DateFormat(format)
        ldt = datetime.now(timezone.utc)
        return format(ldt.astimezone(get_localzone()).isoformat(format))