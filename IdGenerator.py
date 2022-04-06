#Translation of IdGenerator.java from CICFlowMeter package

class IdGenerator():#include parent class
    #generating the numerical ID
    id = 0L #declaring variable id

    def __init__(self):idGenerator(self, id):
        super().idGenerator
        self.id = id #set the id value to the value given

    def idGenerator(self):
        super(self)
        self.id = 0L #set the id value to 0

    def nextId(self):
        with self.lock:
            self.id = self.id + 1 #incrementing the id value to reach the next id
            return self.id

