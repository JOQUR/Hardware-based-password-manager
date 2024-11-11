from IStage import IStage
from ICrypto import ICrypto

class Application(IStage):
    def __init__(self, crypto: ICrypto):
        print("dupa")