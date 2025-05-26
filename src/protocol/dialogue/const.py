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
    TRANSFER_CREDIT = auto()
    REQUEST_WITNESS_SIGNATURE = auto()
    CONFIRM_TRANSACTION = auto()
    RECONFIRM_TRANSACTION = auto()
    REQUEST_HOLD_RECEIPT = auto()
    INFORM_VNT_EVENT = auto()
    CONFIRM_STAKE = auto()

class ControlPacket(StrEnum):
    ACKNOWLEDGEMENT = 'ok'
    REFUSAL = auto()
    ERROR = auto()
    SUCCESS = auto()
    FAILURE = auto()