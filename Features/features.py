import numpy as np


#### FLAG FUNCTIONS ####
def getFinFlagCounts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagFIN():
            counts += 1
    return counts


def getPshFlagCounts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagPSH():
            counts += 1
    return counts


def getUrgFlagCounts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagURG():
            counts += 1
    return counts


def getEceFlagCounts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagECE():
            counts += 1
    return counts


def getSynFlagCounts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagSYN():
            counts += 1
    return counts


def getAckFlagCounts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagACK():
            counts += 1
    return counts


def getCwrFlagCounts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagCWR():
            counts += 1
    return counts


def getRstFlagCounts(packets):
    counts = 0
    for packet in packets:
        if packet.has_flagRST():
            counts += 1
    return counts


###############################

def getFlowDuration(flow):
    return flow.get_flow_last_seen() - flow.get_flow_start_time()


###############################
#### PACKET COUNT ####
def getPacketCount(packets):
    return len(packets)


def getPktsPerSecond(flow):
    try:
        return len(flow.get_packets()) / float(flow_duration(flow))
    except ZeroDivisionError:
        return 0


def getbPktsPerSecond(flow):
    try:
        return len(flow.get_backwardpackets()) / float(flow_duration(flow))
    except ZeroDivisionError:
        return 0


def getfPktsPerSecond(flow):
    try:
        return len(flow.get_forwardpackets()) / float(flow_duration(flow))
    except ZeroDivisionError:
        return 0


###############################

#### PACKET LENGTH ####
def getPacketLengthMax(packets):
    packets_len = [packet.get_length() for packet in packets]
    if packets_len:
        return max(packets_len)
    return 0


def getPacketLengthMin(packets):
    packets_len = [packet.get_length() for packet in packets]
    if packets_len:
        return min(packets_len)
    return 0


def getPacketLengthMean(packets):
    packets_len = [packet.get_length() for packet in packets]
    if packets_len:
        return np.mean(packets_len)
    return 0


def getPacketLengthSum(packets):
    packets_len = [packet.get_length() for packet in packets]
    if packets_len:
        return sum(packets_len)
    return 0


def getPacketLengthStd(packets):
    packets_len = [packet.get_length() for packet in packets]
    if packets_len:
        return np.std(packets_len)
    return 0


##################################
####IAT######

def IAT(packets):  # the code should be improved
    times = [packet.get_timestamp() for packet in packets]
    for i in range(len(times) - 1):
        times[i] = times[i + 1] - times[i]
    if len(times) == 0:
        pass
    else:
        times.pop()
    return times


def getTotalIATmean(packets):
    times = IAT(packets)
    if len(times) == 0:
        return 0
    else:
        return np.mean(times)


def getTotalIATStd(packets):  # should be developed for NaN value
    times = IAT(packets)
    try:
        return np.std(times)
    except RuntimeWarning:
        return None
    except ZeroDivisionError:
        return 0
    except ValueError:
        return 0


def getTotalIATMax(packets):
    times = IAT(packets)
    try:
        return np.max(times)
    except ValueError:
        pass


def getTotalIATMin(packets):
    times = IAT(packets)
    try:
        return np.min(times)
    except ValueError:
        pass


def getTotalIATSum(packets):
    times = IAT(packets)
    return sum(times)


##forward packets IAT ##
def getFwdIATMean(flow):
    fwdPackets = flow.get_forwardpackets()
    times = IAT(fwdPackets)
    if len(times) == 0:
        return 0
    else:
        return np.mean(times)


def getFwdIATStd(flow):
    fwdPackets = flow.get_forwardpackets()
    times = IAT(fwdPackets)
    try:
        return np.std(times)
    except RuntimeWarning:
        return None
    except ZeroDivisionError:
        return None
    except ValueError:
        return None


def getFwdIATMax(flow):
    fwdPackets = flow.get_forwardpackets()
    times = IAT(fwdPackets)
    try:
        return np.max(times)
    except ValueError:
        return None


def getFwdIATMin(flow):
    fwdPackets = flow.get_forwardpackets()
    times = IAT(fwdPackets)
    try:
        return np.min(times)
    except ValueError:
        return None


def getFwdIATSum(flow):
    fwdPackets = flow.get_forwardpackets()
    times = IAT(fwdPackets)
    return sum(times)


##backward packets IAT##
def getBwdIATMean(flow):
    bwdPackets = flow.get_backwardpackets()
    times = IAT(bwdPackets)
    if len(times) == 0:
        return 0
    else:
        return np.mean(times)


def getBwdIATStd(flow):
    bwdPackets = flow.get_backwardpackets()
    times = IAT(bwdPackets)
    try:
        return np.std(times)
    except RuntimeWarning:
        return None
    except ZeroDivisionError:
        return None
    except ValueError:
        return None


def getBwdIATMax(flow):
    bwdPackets = flow.get_backwardpackets()
    times = IAT(bwdPackets)
    try:
        return np.max(times)
    except ValueError:
        return None


def getBwdIATMin(flow):
    bwdPackets = flow.get_backwardpackets()
    times = IAT(bwdPackets)
    try:
        return np.min(times)
    except ValueError:
        return None


def getOwdIATSum(flow):
    bwdPackets = flow.get_backwardpackets()
    times = IAT(bwdPackets)
    return sum(times)


##segment size statistic forward
def getFwdAvgSegmentSize(packets):
    fwdPackets = flow.get_forwardpackets()
    fwdstats = [packets.get_payloadBytes() for packet in packets]
    if (len(fwdPackets) != 0):
        return (sum(fwdstats) / len(fwdPackets))
    return 0

def getBwdAvgSegmentSize(packets):
    bwdPackets = flow.get_backwardpackets()
    bwdstats = [packets.get_payloadBytes() for packet in packets]
    if (len(bwdPackets) != 0):
        return (sum(bwdstats) / len(bwdPackets))
    return 0
def getFwdPpacketLengthMax(packets):
    fwdPackets = flow.get_forwardpackets()
    fwdstats = [packets.get_payloadBytes() for packet in packets]
    if (len(fwdPackets) != 0):
        return max(fwdstats)
    else:
        return 0
def getBwdPacketLengthMin(packets):
    fwdPackets = flow.get_forwardpackets()
    fwdstats = [packets.get_payloadBytes() for packet in packets]
    if (len(fwdPackets) != 0):
        return min(fwdstats)
    else:
        return 0
def getFwdPacketLengthStd(packets):
    fwdPackets = flow.get_forwardpackets()
    fwdstats = [packets.get_payloadBytes() for packet in packets]
    if (len(fwdPackets) != 0):
        return std(fwdstats)
    else:
        return 0
def getBwdPacketLengthMax(packets):
    bwdPackets = flow.get_backwardpackets()
    bwdstats = [packets.get_payloadBytes() for packet in packets]
    if (len(bwdPackets) != 0):
        return max(bwdstats)
    else:
        return 0
def getBwdPacketLengthMin(packets):
    bwdPackets = flow.get_backwardpackets()
    bwdstats = [packets.get_payloadBytes() for packet in packets]
    if (len(bwdPackets) != 0):
        return min(bwdstats)
    else:
        return 0
def getBwdPacketLengthStd(packets):
    bwdPackets = flow.get_forwardpackets()
    bwdstats = [packets.get_payloadBytes() for packet in packets]
    if (len(bwdPackets) != 0):
        return std(bwdstats)
    else:
        return 0

##idle time features
def updateActiveIdle(flow, threshold):
    current_time = get_flow_last_seen()
    if ((current_time - flow.end_active_time) > threshold):
        if((flow.end_active_time - flow.start_active_time) > 0):
            flow.flow_active.append(flow.end_active_time - flow.start_active_time)
        flow.flow_idle.append(current_time - flow.end_active_time)
        flow.end_active_time = current_time
        flow.start_active_time = current_time
    else:
        flow.end_active_time = current_time

def getDownUpRatio(flow):
    if (flow.forwardpackets.size() > 0 ):
        return flow.backwardpackets.size() / flow.forwardpackets.size()
    return 0
def getIdleMin(flow):
    if(len(flow.flow_idle) > 0):
        return min(flow.flow_idle)
    else:
        return 0
def getIdleMax(flow):
    if(len(flow.flow_idle) > 0):
        return max(flow.flow_idle)
    else:
        return 0
def getIdleStd(flow):
    if(len(flow.flow_idle) > 0):
        return std(flow.flow_idle)
    else:
        return 0

def getIdleMean(flow):
    if(len(flow.flow_idle) > 0):
        return sum(flow.flow_idle) / len(flow.flow_idle)
    else:
        return 0
    
##header features
def getBwdHeaderLength(self, packet):
    for i in self.backwardpackets:
        if(i == packet):
            return len(packet.show())
        else:
            return 0

def getFwdHeaderLength(self, packet):
    for i in self.forwardpackets:
        if (i == packet):
            return len(packet.show())
        else:
            return 0
        
def getBwdHeaderByte(self, packet):
    for i in self.backwardpackets:
        if(i == packet):
            return byte(packet.show())
        else:
            return 0

def getFwdHeaderByte(self, packet):
    for i in self.forwardpackets:
        if (i == packet):
            return byte(packet.show())
        else:
            return 0
#################################
