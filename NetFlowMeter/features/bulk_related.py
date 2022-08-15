from .feature import Feature


# Client average bytes per bulk
class fAvgBytesPerBulk(Feature):
# def fAvgBytesPerBulk(flow):
    name = "Fwd Bytes/Bulk Avg"
    def extract(self, flow: object) -> float:
        if flow.fBulkStateCount() != 0:
            return (flow.fBulkSizeTotal() / flow.fBulkStateCount())
        return 0

# Client average packet per bulk
class fAvgPacketsPerBulk(Feature):
# def fAvgPacketsPerBulk(flow):
    name='Fwd Packet/Bulk Avg'
    def extract(self, flow: object) -> dict:
        if flow.fBulkStateCount() != 0:
            return flow.fBulkPacketCount() / flow.fBulkStateCount()
        return 0

# Client average bulk rate
class fAvgBulkRate(Feature):
    # def fAvgBulkRate(flow):
    name = "Fwd Bulk Rate Avg"
    def extract(self, flow: object) -> dict:
        if flow.fBulkDuration() != 0:
            return flow.fBulkSizeTotal() / flow.fBulkDuration()
        return 0



# Client average bytes per bulk
class bAvgBytesPerBulk(Feature):
    name = "Bwd Bytes/Bulk Avg"
# def bAvgBytesPerBulk(flow):
    def extract(self, flow: object) -> dict:
        if flow.bbulkStateCount != 0:
            return (flow.bBulkSizeTotal() / flow.bBulkStateCount())
        return 0

# Client average packet per bulk
class bAvgPacketsBulkRate(Feature):
# def bAvgPacketsBulkRate(flow):
    name = "Bwd Packet/Bulk Avg"
    def extract(self, flow: object) -> dict:
        if flow.bBulkStateCount() != 0:
            return flow.bBulkPacketCount() / flow.bBulkStateCount()
        return 0

# Client average bulk rate
class bAvgBulkRate(Feature):
    name = "Bwd Bulk Rate Avg"
# def bAvgBulkRate(flow):
    def extract(self, flow: object) -> dict:
        if flow.bBulkDuration() != 0:
            return flow.bBulkSizeTotal() / flow.bBulkDuration()
        return 0



###################################features which are in the class flow################################

# def fBulkStateCount(self):
class fBulkStateCount(Feature):
    name = "Fwd bulk state count"
    def extract(self, flow: object) -> dict:
        return self.fbulkStateCount

# def fBulkSizeTotal(self):
class fBulkSizeTotal(Feature):
    name = "Fwd bulk total size"
    def extract(self, flow: object) -> dict:
        return self.fbulkSizeTotal

# def fBulkPacketCount(self):
class fBulkPacketCount(Feature):
    name = "Fwd bulk per packet"
    def extract(self, flow: object) -> dict:
        return self.fbulkPacketCount

#def fBulkDuration(self):
class fBulkDuration(Feature):
    name = "Fwd bulk Duration"
    def extract(self, flow: object) -> dict:
        return self.fbulkDuration

# def bBulkStateCount(self):
class bBulkStateCount(Feature):
    name = "Bwd bulk state count"
    def extract(self, flow: object) -> dict:
        return self.bbulkStateCount

# def bBulkSizeTotal(self):
class bBulkSizeTotal(Feature):
    name = "Bwd bulk total size"
    def extract(self, flow: object) -> dict:
        return self.bbulkSizeTotal

# def bBulkPacketCount(self):
class bBulkPacketCount(Feature):
    name = "Bwd bulk per packet"
    def extract(self, flow: object) -> dict:
         return self.bbulkPacketCount

# def bBulkDuration(self):
class bBulkDuration(Feature):
    name ="Bwd bulk Duration"
    def extract(self, flow: object) -> dict:
         return self.bbulkDuration
