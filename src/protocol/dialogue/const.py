from enum import StrEnum, auto
class DialogueEnum(StrEnum):
    TEMPLATE = auto()
    HANDSHAKE = auto()
    REQUEST_ADD_SELF = auto()
    REQUEST_NODE_LIST = auto()
    SYNC_VNT = auto()
    GET_LATEST_HASH = auto()
    CHECK_SAME_VNT = auto()
    REQUEST_MISSING_EVENTS = auto()
    SEND_MISSING_EVENTS = auto()
    TRANSFER_CURRENCY = auto()

class ControlPacket(StrEnum):
    ACKNOWLEDGEMENT = 'ok'
    REFUSAL = auto()
    ERROR = auto()
    SUCCESS = auto()
    FAILURE = auto()