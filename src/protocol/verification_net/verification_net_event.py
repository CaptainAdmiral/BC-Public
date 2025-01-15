from abc import ABC, abstractmethod
from enum import StrEnum, auto
from typing import Any, Hashable, Optional

from pydantic import BaseModel
from protocol.std_protocol.std_protocol import VerificationNodeData
from util.timestamped import Timestamped

class VerificationNetEventEnum(StrEnum):
    NODE_JOIN = auto()
    '''New node joins the verification network'''
    NODE_LEAVE = auto()
    '''Node leaves the verification network'''
    NODE_PAUSE = auto()
    '''Node stops taking verification requests temporarily'''
    NODE_RESUME = auto()
    '''Node resumes taking verification requests'''
    ADD_ENTROPY = auto()
    '''Occasionally broadcast to prevent manipulation of the verification timeline as a source of randomness'''

class VNTEventPacket(BaseModel, Timestamped):
    event_type: VerificationNetEventEnum
    timestamp: float
    data: Any
    hash: Optional[int]

class VerificationNetEvent(ABC, Timestamped):
    event_type: VerificationNetEventEnum

    def __init__(self, timestamp: float, data: Hashable, prev_hash: int = 0):
        self.timestamp = timestamp
        self.data = data
        self.verified_signatures = False
        self.prev_hash = prev_hash
        self.update_checksum()

    def __eq__(self, other):
        return isinstance(other, VerificationNetEvent) and self.checksum == other.checksum
    
    def __hash__(self):
        return self.checksum
    
    def update_checksum(self):
        self.checksum = hash((self.event_type, self.timestamp, hash(self.data), self.prev_hash))
    
    def to_packet(self):
        return VNTEventPacket(
            event_type=self.event_type,
            timestamp=self.timestamp,
            data=self.data,
            hash=self.checksum
        )
    
    @abstractmethod
    def update_verification_list(self, verification_list: list[VerificationNodeData]):
        ...

    @abstractmethod
    def verify_signatures(self):
        '''Checks the digital signatures involved with the event are valid and raises an exception if not'''
        self.verified_signatures = True

    @abstractmethod
    def validate(self):
        '''Validates that the signatures are valid, signed by known nodes in the network, and that the chosen verifiers are all within acceptable probability bounds.
        Raises an exception if validation fails'''
        self.verify_signatures()

class VNTEventFactory:
    vntEvents: list[type[VerificationNetEvent]] = []

    @classmethod
    def from_packet(cls, packet: VNTEventPacket) -> VerificationNetEvent:
        return next(t for t in cls.vntEvents if t.event_type == packet.event_type)(packet.timestamp, packet.data)