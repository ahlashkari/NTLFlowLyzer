##bulk


# Client average bytes per bulk
def fAvgBytesPerBulk(flow):
    if flow.fBulkStateCount() != 0:
        return (flow.fBulkSizeTotal() / flow.fBulkStateCount())
    return 0

# Client average packet per bulk
def fAvgPacketsPerBulk(flow):
    if flow.fBulkStateCount() != 0:
        return flow.fBulkPacketCount() / flow.fBulkStateCount()

# Client average bulk rate
def fAvgBulkRate(flow):
    if flow.fBulkDuration() != 0:
        return flow.fBulkSizeTotal() / flow.fBulkDuration()
    return 0


# def bBulkDurationInSecond(flow):
#     return flow.bbulkDuration / 1000000

# Client average bytes per bulk
def bAvgBytesPerBulk(flow):
    if flow.bbulkStateCount != 0:
        return (flow.bBulkSizeTotal() / flow.bBulkStateCount())
    return 0

# Client average packet per bulk
def bAvgPacketsBulkRate(flow):
    if flow.bBulkStateCount() != 0:
        return flow.bBulkPacketCount() / flow.bBulkStateCount()
    return 0

# Client average bulk rate
def bAvgBulkRate(flow):
    if flow.bBulkDuration() != 0:
        return flow.bBulkSizeTotal() / flow.bBulkDuration()
    return 0


