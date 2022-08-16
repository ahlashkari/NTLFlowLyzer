from .feature import Feature


class AvgFwdBytesPerBulk(Feature):
    name = "avg_fwd_bytes_per_bulk"
    def extract(self, flow: object) -> float:
        if flow.fBulkStateCount() != 0:
            return (flow.fBulkSizeTotal() / flow.fBulkStateCount())
        return 0


class AvgFwdPacketsPerBulk(Feature):
    name='avg_fwd_packets_per_bulk'
    def extract(self, flow: object) -> dict:
        if flow.fBulkStateCount() != 0:
            return flow.fBulkPacketCount() / flow.fBulkStateCount()
        return 0


class AvgFwdBulkRate(Feature):
    name = "avg_fwd_bulk_rate"
    def extract(self, flow: object) -> dict:
        if flow.fBulkDuration() != 0:
            return flow.fBulkSizeTotal() / flow.fBulkDuration()
        return 0


class AvgBwdBytesPerBulk(Feature):
    name = "avg_bwd_bytes_per_bulk"
    def extract(self, flow: object) -> dict:
        if flow.bbulkStateCount != 0:
            return (flow.bBulkSizeTotal() / flow.bBulkStateCount())
        return 0


class AvgBwdPacketsPerBulk(Feature):
    name = "avg_bwd_packets_bulk_rate"
    def extract(self, flow: object) -> dict:
        if flow.bBulkStateCount() != 0:
            return flow.bBulkPacketCount() / flow.bBulkStateCount()
        return 0


class AvgBwdBulkRate(Feature):
    name = "avg_bwd_bulk_rate"
    def extract(self, flow: object) -> dict:
        if flow.bBulkDuration() != 0:
            return flow.bBulkSizeTotal() / flow.bBulkDuration()
        return 0


class FwdBulkStateCount(Feature):
    name = "fwd_bulk_state_count"
    def extract(self, flow: object) -> dict:
        return self.fbulkStateCount()


class FwdBulkSizeTotal(Feature):
    name = "fwd_bulk_total_size"
    def extract(self, flow: object) -> dict:
        return self.fbulkSizeTotal()


class FwdBulkPacketCount(Feature):
    name = "fwd_bulk_per_packet"
    def extract(self, flow: object) -> dict:
        return self.fbulkPacketCount()


class FwdBulkDuration(Feature):
    name = "fwd_bulk_duration"
    def extract(self, flow: object) -> dict:
        return self.fbulkDuration()


class BwdBulkStateCount(Feature):
    name = "bwd_bulk_state_count"
    def extract(self, flow: object) -> dict:
        return self.bbulkStateCount()


class BwdBulkSizeTotal(Feature):
    name = "bwd_bulk_total_size"
    def extract(self, flow: object) -> dict:
        return self.bbulkSizeTotal()


class BwdBulkPacketCount(Feature):
    name = "bwd_bulk_per_packet"
    def extract(self, flow: object) -> dict:
         return self.bbulkPacketCount()


class BwdBulkDuration(Feature):
    name ="bwd_bulk_duration"
    def extract(self, flow: object) -> dict:
         return self.bbulkDuration()
