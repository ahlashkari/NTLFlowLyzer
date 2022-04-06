#Translating BasicPacketInfo.java from the CICFlowMeter package

class BasicPacketInfo:
    #this class provides the basic info needed to generate flows from given packets
    #declaring variables
    id = 0L
    src = []
    dst = []
    srcPort = 0
    dstPort = 0
    protocol = 0
    timeStamp = 0
    payloadBytes = 0
    flowId = ""
    flagFIN = false
    flagPSH = false
    flagURG = false
    flagECE = false
    flagSYN = false
    flagACK = false
    flagCWR = false
    flagRST = false
    TCPWindow = 0
    headerBytes = 0L
    payloadPacket = 0

    #constructors
    def BasicPacketInfo(self, src, dst, srcPort, dstPort,protocol, timeStamp, generator):
        super(self)     ####look into super() function
        self.id = generator.nextId() ##how can i do this in python
        self.src = src
        self.dst = dst
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.protocol = protocol
        self.timeStamp = timeStamp
        generateFlowId()

    def BasicPacketInfo(self, generator):
        super(self)
        self.id = generator.nextId() ##???

    def generateFlowId(self):
        forward = True
        for i in len(src):
            if (((Byte)(this.src[i])).intValue() != ((Byte)(self.dst[i])).intValue()):
                if (((Byte)(this.src[i])).intValue() > ((Byte)(this.dst[i])).intValue()):
                   forward = False
                   i=len(self.src)
        if (forward):
           self.flowId = self.getSourceIP() + "-" + self.getDestinationIP() + "-" + self.srcPort  + "-" + self.dstPort  + "-" + self.protocol
        else:
           self.flowId = self.getDestinationIP() + "-" + self.getSourceIP() + "-" + self.dstPort  + "-" + self.srcPort  + "-" + self.protocol

        return self.flowId


    def fwdFlowId(self):
       self.flowId = self.getSourceIP() + "-" + self.getDestinationIP() + "-" + self.srcPort + "-" + self.dstPort + "-" + self.protocol
       return self.flowId




    def bwdFlowId(self):
       self.flowId = self.getDestinationIP() + "-" + self.getSourceIP() + "-" + self.dstPort + "-" + self.srcPort + "-" + self.protocol
       return self.flowId

#setters and getters
    def dumpInfo(self):
        return null

    def getPayloadPacket(self):
        self.payloadPacket = self.payloadPacket + 1
        return self.payloadPacket

    def getSourceIP(self):
        return FormatUtils.ip(self.src)

    def getDestinationIP(self):
        return FormatUtils.ip(self.dst)

    def getId(self):
        return id

    def setId(self, id):
        self.id = id

    def getSrc(self):
        return copyOf(src, len(src))

    def setSrc(self, src):
        self.src = src

    def getDst(self):
        return copyOf(dst, len(dst))

    def setDst(self, dst):
        self.dst = dst

    def getSrcPort(self):
        return srcPort

    def setSrcPort(self, srcPort):
        self.srcPort = srcPort

    def getDstPort(self):
        return dstPort

    def setDstPort(self, dstPort):
        self.dstPort = dstPort

    def getProtocol(self):
        return protocol

    def setProtocol(self, protocol):
        self.protocol = protocol

    def getTimeStamp(self):
        return timeStamp

    def setTimeStamp(self, timeStamp):
        self.timeStamp = timeStamp

    def getFlowId(self):
        if (self.flowId != null):
            return self.flowId
        else:
            return generateFlowId()

    def setFlowId(self, flowId):
        self.flowId = flowId

    def isForwardPacket(self, sourceIP):
        return (sourceIP == self.src)

    def getPayloadBytes(self):
        return payloadBytes

    def setPayloadBytes(self, payloadBytes):
        self.payloadBytes = payloadBytes

    def getHeaderBytes(self):
        return headerBytes

    def setHeaderBytes(self, headerBytes):
        self.headerBytes = headerBytes

    def hasFlagFIN(self):
        return flagFIN

    def setFlagFIN(self, flagFIN):
        self.flagFIN = flagFIN

    def hasFlagPSH(self):
        return flagPSH

    def setFlagPSH(self, flagPSH):
        self.flagPSH = flagPSH

    def hasFlagURG(self):
        return flagURG

    def setFlagURG(self, flagURG):
        self.flagURG = flagURG

    def hasFlagECE(self):
        return flagECE

    def setFlagECE(self, flagECE):
        self.flagECE = flagECE

    def hasFlagSYN(self):
        return flagSYN

    def setFlagSYN(self, flagSYN):
        self.flagSYN = flagSYN

    def hasFlagACK(self):
        return flagACK

    def setFlagACK(self, flagACK):
        self.flagACK = flagACK

    def hasFlagCWR(self):
        return flagCWR

    def setFlagCWR(self, flagCWR):
        self.flagCWR = flagCWR;

    def hasFlagRST(self):
        return flagRST

    def setFlagRST(slef, flagRST):
        self.flagRST = flagRST

    def getTCPWindow(self):
        return TCPWindow

    def setTCPWindow(self, TCPWindow):
        self.TCPWindow = TCPWindow



    ## auxilary methods
    def copy_of(lst, length):
        out = lst.copy()  # This is a shallow copy.
        # For deepcopy use `copy.deepcopy(lst)`
        out[length:] = [0 for _ in range(length - len(lst))]
        return out


