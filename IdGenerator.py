#Translation of IdGenerator.java from CICFlowMeter package

import threading

class IdGenerator():
    #generating the numerical ID
    id = 0 #declaring variable id

    def __init__(self, id=0):
        self.id = id #set the id value to the value given
        self.lock = threading.Lock()

    def nextId(self):
      self.lock.acquire()
      self.id = self.id + 1 #incrementing the id value to reach the next id
      self.lock.release()


