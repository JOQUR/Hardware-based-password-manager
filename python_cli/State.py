from enum import IntEnum

class State(IntEnum):
    HELLO = 0
    CHALLANGE = 1
    AUTHENTICATED = 2
    APP_START = 3
    ERROR = 4