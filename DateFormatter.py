#Translating DateFormatter.java from CICFlowMeter package

import time
from datetime import datetime, timezone

from datetime import date

class DateFormatter:
    def __init__(self,time,format= "%m/%d/%Y, %H:%M:%S"):
        self.time=time
        self.format=format

    def parseDateFromLong(self):

                return self.time.strftime("%m/%d/%Y, %H:%M:%S")


    def converMilliseconds2String(self):

        date_s = datetime.now().isoformat(sep=' ', timespec='milliseconds')

        return  date_s.replace('-','/')
