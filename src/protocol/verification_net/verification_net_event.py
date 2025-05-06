from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum, auto
from typing import Any, Hashable

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

@dataclass(frozen=True)
class VNTEventPacket(Timestamped):
    event_type: VerificationNetEventEnum
    timestamp: float
    data: Any
    checksum: str

    def __eq__(self, other):
        return isinstance(other, VNTEventPacket) and self.checksum == other.checksum

    def __hash__(self) -> int:
        return hash((self.event_type, self.timestamp, self.data))

class VerificationNetEvent(ABC, Timestamped):
    event_type: VerificationNetEventEnum

    def __init__(self, timestamp: float, data: Hashable):
        self.timestamp = timestamp
        self.data = data
        self.validated = False
        self.prev_hash = ''
        self.update_checksum()

    def __eq__(self, other):
        return isinstance(other, VerificationNetEvent) and self.checksum == other.checksum
    
    def __hash__(self):
        return hash((self.event_type, self.timestamp, self.data))
    
    @property
    def id(self) -> str:
        return str(hash(self))
    
    def update_checksum(self):
        self.checksum = str(hash((self.event_type, self.timestamp, self.data, self.prev_hash)))
    
    def to_packet(self):
        return VNTEventPacket(
            event_type=self.event_type,
            timestamp=self.timestamp,
            data=self.data,
            checksum=self.checksum
        )
    
    @abstractmethod
    def update_verification_list(self, verification_list: list[VerificationNodeData]):
        ... # TODO

    @abstractmethod
    def verify_checksum(self):
        '''Checks the checksums involved with the event are valid and raises an exception if not'''
        ...

    @abstractmethod
    def validate(self):
        '''Validates that the checksums are valid, and performs any other necessary validation logic for the event.
        Raises an exception if validation fails'''
        self.verify_checksum()
        self.validated = True

class VNTEventFactory:
    vntEvents: list[type[VerificationNetEvent]] = []

    @classmethod
    def from_packet(cls, packet: VNTEventPacket) -> VerificationNetEvent:
        return next(t for t in cls.vntEvents if t.event_type == packet.event_type)(packet.timestamp, packet.data)