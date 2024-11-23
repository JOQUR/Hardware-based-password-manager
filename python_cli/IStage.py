from abc import ABC, abstractmethod
from ICrypto import ICrypto

class IStage(ABC):
    def __init__(self, crypto):
        self.crypto = crypto