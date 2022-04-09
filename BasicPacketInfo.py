#Translating BasicPacketInfo.java from the CICFlowMeter package
Import IdGenerator

class BasicPacketInfo:
    #this class provides the basic info needed to generate flows from given packets
    #declaring variables
    
    payloadBytes = 0
    flagFIN = False
    flagPSH = False
    flagURG = False
    flagECE = False
    flagSYN = False
    flagACK = False
    flagCWR = False
    flagRST = False
    TCPWindow = 0
    headerBytes = 0
    payloadPacket = 0

    #constructors

    def __init__(self, id=0 ,src=[], dst=[], srcPort=0, dstPort=0, protocol=0, timeStamp=0, flowId=''):
      idgen = IdGenerator()
      self.id = idgen.nextId()
      self.src = src
      self.dst = dst
      self.srcPort = srcPort
      self.dstPort = dstPort
      self.protocol = protocol
      self.timeStamp = timeStamp
      self.flowId = self.generateFlowId()


    def generateFlowId(self):
        forward = True
        for i in len(self.src):
            if ((bytes(self.src[i])).intValue() != (bytes(self.dst[i])).intValue()):
                if ((bytes(self.src[i])).intValue() > (bytes(self.dst[i])).intValue()):
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
        return None

    def getPayloadPacket(self):
        self.payloadPacket = self.payloadPacket + 1
        return self.payloadPacket

    def getSourceIP(self):
        return self.src #FormatUtils.ip(self.src) was deleted-  find the substitute in python  #issue

    def getDestinationIP(self):
        return self.dst #FormatUtils.ip(self.src) was deleted-  find the substitute in python  #issue

    def getId(self):
        return self.id

    def setId(self, id):
        self.id = id

    '''def getSrc(self):
        return copyOf(self.src, len(self.src)) '''

    def setSrc(self, src):
        self.src = src

    '''def getDst(self):
        return copyOf(self.dst, len(self.flagCWRdst)) '''

    def setDst(self, dst):
        self.dst = dst

    def getSrcPort(self):
        return self.srcPort

    def setSrcPort(self, srcPort):
        self.srcPort = srcPort

    def getDstPort(self):
        return self.dstPort

    def setDstPort(self, dstPort):
        self.dstPort = dstPort

    def getProtocol(self):
        return self.protocol

    def setProtocol(self, protocol):
        self.protocol = protocol

    def getTimeStamp(self):
        return self.timeStamp

    def setTimeStamp(self, timeStamp):
        self.timeStamp = timeStamp

    def getFlowId(self):
        if (self.flowId != None):
            return self.flowId
        else:
            return self.generateFlowId()

    def setFlowId(self, flowId):
        self.flowId = flowId

    def isForwardPacket(self, sourceIP):
        return (sourceIP == self.src)

    def getPayloadBytes(self):
        return self.payloadBytes

    def setPayloadBytes(self, payloadBytes):
        self.payloadBytes = payloadBytes

    def getHeaderBytes(self):
        return self.headerBytes

    def setHeaderBytes(self, headerBytes):
        self.headerBytes = headerBytes

    def hasFlagFIN(self):
        return self.flagFIN

    def setFlagFIN(self, flagFIN):
        self.flagFIN = flagFIN

    def hasFlagPSH(self):
        return self.flagPSH

    def setFlagPSH(self, flagPSH):
        self.flagPSH = flagPSH

    def hasFlagURG(self):
        return self.flagURG

    def setFlagURG(self, flagURG):
        self.flagURG = flagURG

    def hasFlagECE(self):
        return self.flagECE

    def setFlagECE(self, flagECE):
        self.flagECE = flagECE

    def hasFlagSYN(self):
        return self.flagSYN

    def setFlagSYN(self, flagSYN):
        self.flagSYN = flagSYN

    def hasFlagACK(self):
        return self.flagACK

    def setFlagACK(self, flagACK):
        self.flagACK = flagACK

    def hasFlagCWR(self):
        return self.flagCWR

    def setFlagCWR(self, flagCWR):
        self.flagCWR = flagCWR;

    def hasFlagRST(self):
        return self.flagRST

    def setFlagRST(self, flagRST):
        self.flagRST = flagRST

    def getTCPWindow(self):
        return self.TCPWindow

    def setTCPWindow(self, TCPWindow):
        self.TCPWindow = TCPWindow



    ## auxilary methods
    '''def copy_of(lst, length):
        out = lst.copy()  # This is a shallow copy.
        # For deepcopy use `copy.deepcopy(lst)`
        out[length:] = [0 for _ in range(length - len(lst))]
        return out'''


