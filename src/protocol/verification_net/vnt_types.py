from abc import ABC, abstractmethod
from enum import StrEnum, auto
from typing import Hashable, Protocol
from cryptography.util import to_sha256
from util.timestamped import Timestamped
from dataclasses import dataclass, replace
from uuid import UUID
from cryptography.signature import Signed
from protocol.credit.credit_types import Stake
from protocol.dialogue.base_dialogue import DialogueException
from protocol.std_protocol.std_protocol import StdProtocol, VerificationNodeData
from settings import TIME_TO_CONSISTENCY, VERIFIER_REDUNDANCY
from timeline import cur_time

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
class VNTEventPacket:
    event_type: VerificationNetEventEnum
    data: str
    '''Json serialized event data'''

class VNTUpdateHelper:

    def __init__(self):
        self.left_network: set[VerificationNodeData] = set() 
        self.paused: set[VerificationNodeData] = set()
        self.joined_network: list[VerificationNodeData] = []

    def add(self, node_data: VerificationNodeData):
        if node_data in self.left_network:
            self.left_network.remove(node_data) 
        self.joined_network.append(node_data)
    
    def remove(self, node_data: VerificationNodeData):
        self.left_network.add(node_data)
    
    def pause_node(self, node_data: VerificationNodeData):
        self.paused.add(node_data)
    
    def resume_node(self, node_data: VerificationNodeData):
        self.paused.remove(node_data)
    
    def to_list(self):
        already_present = set()
        verification_nodes = []
        for node in reversed(self.joined_network):
            if node in already_present or node in self.left_network:
                continue

            if node in self.paused:
                assert(hasattr(node, 'paused'))
                node = replace(node, paused=True)

            already_present.add(node)
            verification_nodes.append(node)     

        verification_nodes.reverse()
        return verification_nodes

class HashableTimestamped(Hashable, Timestamped, Protocol):
    ...

class VerificationNetEvent[T: HashableTimestamped](ABC, Timestamped):

    def __init__(self, data: T, signed_vnt_packet: Signed[VNTEventPacket]):
        self._timestamp = data.timestamp
        self.data = data
        self.prev_hash = ''
        self.signed_vnt_packet = signed_vnt_packet
        self.id = to_sha256((self.event_type, self.timestamp, self.data))
        self.update_checksum()
    
    @property
    def timestamp(self):
        return self._timestamp

    def __eq__(self, other):
        return isinstance(other, VerificationNetEvent) and self.id == other.id
    
    def __hash__(self):
        return hash((self.event_type, self.data))

    @property
    @abstractmethod
    def event_type(self) -> VerificationNetEventEnum:
        ...

    def update_checksum(self):
        self.checksum = to_sha256((self.id, self.prev_hash)) 
    
    def get_packet(self):
        return self.signed_vnt_packet    
    
    @abstractmethod
    def update_verification_list(self, vnt_update_obj: VNTUpdateHelper):
        '''Defines how to update the final list of nodes based on this event in the VNT'''
        ...
    
    @abstractmethod
    def validate(self, protocol: StdProtocol):
        ...

class JoinEvent(VerificationNetEvent[Stake]):

    def __init__(self, data: Stake, signed_vnt_packet: Signed[VNTEventPacket]):
        super().__init__(data, signed_vnt_packet)

    @property
    def event_type(self):
        return VerificationNetEventEnum.NODE_JOIN

    def update_verification_list(self, vnt_update_obj: VNTUpdateHelper):
        stake = self.data
        vnt_update_obj.add(stake.get_node())

    def validate(self, protocol: StdProtocol):
        timestamp = cur_time()

        self.signed_vnt_packet.validate_signatures()
        stake = self.data

        if self.signed_vnt_packet.signed_by_N0():
            return

        if not self.signed_vnt_packet.signed_by(stake.public_key):
            raise DialogueException("Invalid signatures for event")

        if stake.timestamp < timestamp - TIME_TO_CONSISTENCY:
            raise DialogueException('Stake expired') # Prevents old stakes from being reused to join vnt

        stake.validate_funds(protocol)
        for fund in stake.funds:
            relevant_signatories = set(sig.public_key for sig in self.signed_vnt_packet.signatures if sig.public_key in (witness.public_key for witness in fund.witnesses))
            
            if len(relevant_signatories) < VERIFIER_REDUNDANCY:
                raise DialogueException('Not enough signatures on fund for stake')

@dataclass(frozen=True)
class LeaveData:
    stake_id: UUID
    stake_witnesses: tuple[VerificationNodeData, ...]
    fund_ids: tuple[str, ...]
    _timestamp: float
    node: VerificationNodeData

    @property
    def timestamp(self):
        return self._timestamp

class LeaveEvent(VerificationNetEvent[LeaveData]):

    def __init__(self, data: LeaveData, vnt_event_packet: Signed[VNTEventPacket]):
        super().__init__(data, vnt_event_packet)

    @property
    def event_type(self):
        return VerificationNetEventEnum.NODE_LEAVE

    def update_verification_list(self, vnt_update_obj: VNTUpdateHelper):
        vnt_update_obj.remove(self.data.node)
    
    def validate(self, protocol: StdProtocol):
        self.signed_vnt_packet.validate_signatures()
        if self.signed_vnt_packet.signed_by_N0():
            return

        if not self.signed_vnt_packet.signed_by(self.data.node.public_key):
            raise DialogueException("Invalid signatures for event")

@dataclass(frozen=True)
class PauseData:
    timestamp: float
    node: VerificationNodeData

class PauseEvent(VerificationNetEvent[PauseData]):

    def __init__(self, data: PauseData, vnt_event_packet: Signed[VNTEventPacket]):
        super().__init__(data, vnt_event_packet)

    @property
    def event_type(self):
        return VerificationNetEventEnum.NODE_PAUSE

    def update_verification_list(self, vnt_update_obj: VNTUpdateHelper):
        vnt_update_obj.pause_node(self.data.node)
    
    def validate(self, protocol: StdProtocol):
        self.signed_vnt_packet.validate_signatures()
        if self.signed_vnt_packet.signed_by_N0():
            return

        if not self.signed_vnt_packet.signed_by(self.data.node.public_key):
            raise DialogueException("Invalid signatures for event")

@dataclass(frozen=True)
class ResumeData:
    timestamp: float
    node: VerificationNodeData

class ResumeEvent(VerificationNetEvent[ResumeData]):

    def __init__(self, data: ResumeData, vnt_event_packet: Signed[VNTEventPacket]):
        super().__init__(data, vnt_event_packet)

    @property
    def event_type(self):
        return VerificationNetEventEnum.NODE_RESUME

    def update_verification_list(self, vnt_update_obj: VNTUpdateHelper):
        vnt_update_obj.resume_node(self.data.node)
    
    def validate(self, protocol: StdProtocol):
        self.signed_vnt_packet.validate_signatures()
        if self.signed_vnt_packet.signed_by_N0():
            return

        if not self.signed_vnt_packet.signed_by(self.data.node.public_key):
            raise DialogueException("Invalid signatures for event")

@dataclass(frozen=True)
class EntropyData:
    timestamp: float
    node: VerificationNodeData
    entropy: str

class EntropyEvent(VerificationNetEvent[EntropyData]):

    def __init__(self, data: EntropyData, vnt_event_packet: Signed[VNTEventPacket]):
        super().__init__(data, vnt_event_packet)

    @property
    def event_type(self):
        return VerificationNetEventEnum.ADD_ENTROPY

    def update_verification_list(self, vnt_update_obj: VNTUpdateHelper):
        ...
    
    def validate(self, protocol: StdProtocol):
        self.signed_vnt_packet.validate_signatures()
        if self.signed_vnt_packet.signed_by_N0():
            return

        if not self.signed_vnt_packet.signed_by(self.data.node.public_key):
            raise DialogueException("Invalid signatures for event")