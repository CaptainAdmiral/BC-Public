from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from enum import StrEnum, auto
from typing import TYPE_CHECKING, Annotated, Any, Hashable, Literal, Protocol
from uuid import UUID

from pydantic import Discriminator, Tag

from crypto.signature import Signed
from crypto.util import to_sha256
from protocol.credit.credit_types import Stake
from protocol.dialogue.dialogue_types import DialogueException
from protocol.dialogue.util.witness_selection_util import validate_signature_count
from protocol.protocols.common_types import VerificationNodeData
from settings import TIME_TO_CONSISTENCY
from timeline import cur_time
from util.timestamped import Timestamped

if TYPE_CHECKING:
    from protocol.verification_net.verification_net_timeline import (
        VerificationNetTimeline,
    )


class VerificationNetEventEnum(StrEnum):
    NODE_JOIN = auto()
    """New node joins the verification network"""
    NODE_LEAVE = auto()
    """Node leaves the verification network"""
    NODE_PAUSE = auto()
    """Node stops taking verification requests temporarily"""
    NODE_RESUME = auto()
    """Node resumes taking verification requests"""
    ADD_ENTROPY = auto()
    """Occasionally broadcast to prevent manipulation of the verification timeline as a source of randomness"""


def get_discriminator_value(v: Any) -> str:
    if isinstance(v, dict):
        return v["event_type"]
    return getattr(v, "event_type")


VNTEventDataTypes = (
    Annotated["JoinData", Tag(VerificationNetEventEnum.NODE_JOIN)]
    | Annotated["LeaveData", Tag(VerificationNetEventEnum.NODE_LEAVE)]
    | Annotated["PauseData", Tag(VerificationNetEventEnum.NODE_PAUSE)]
    | Annotated["ResumeData", Tag(VerificationNetEventEnum.NODE_RESUME)]
    | Annotated["EntropyData", Tag(VerificationNetEventEnum.ADD_ENTROPY)]
)


@dataclass(frozen=True)
class VNTEventPacket:
    data: Annotated[VNTEventDataTypes, Discriminator(get_discriminator_value)]


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
                assert hasattr(node, "paused")
                node = replace(node, paused=True)

            already_present.add(node)
            verification_nodes.append(node)

        verification_nodes.reverse()
        return verification_nodes


class HashableTimestamped(Hashable, Timestamped, Protocol): ...


class VerificationNetEvent[T: HashableTimestamped](ABC, Timestamped):

    def __init__(self, data: T, signed_vnt_packet: Signed[VNTEventPacket]):
        self._timestamp = data.timestamp
        self.data = data
        self.prev_hash = ""
        self.signed_vnt_packet = signed_vnt_packet
        self.id = to_sha256((self.event_type(), self.timestamp, self.data))
        self.update_checksum()

    @property
    def timestamp(self):
        return self._timestamp

    def __eq__(self, other):
        return isinstance(other, VerificationNetEvent) and self.id == other.id

    def __hash__(self):
        return hash((self.event_type(), self.data))

    @classmethod
    @abstractmethod
    def event_type(cls) -> VerificationNetEventEnum: ...

    def update_checksum(self):
        self.checksum = to_sha256((self.id, self.prev_hash))

    def get_packet(self):
        return self.signed_vnt_packet

    @abstractmethod
    def update_verification_list(self, vnt_update_obj: VNTUpdateHelper):
        """Defines how to update the final list of nodes based on this event in the VNT"""
        ...

    @abstractmethod
    def validate(self, vnt: "VerificationNetTimeline"): ...


@dataclass(frozen=True)
class VNTEventData(ABC):
    event_type: VerificationNetEventEnum


@dataclass(frozen=True)
class JoinData(VNTEventData):
    event_type: Literal[VerificationNetEventEnum.NODE_JOIN]
    signed_stake: Signed[Stake]
    timestamp: float


class JoinEvent(VerificationNetEvent[JoinData]):

    def __init__(self, data: JoinData, signed_vnt_packet: Signed[VNTEventPacket]):
        super().__init__(data, signed_vnt_packet)

    @classmethod
    def event_type(cls):
        return VerificationNetEventEnum.NODE_JOIN

    def update_verification_list(self, vnt_update_obj: VNTUpdateHelper):
        stake = self.data.signed_stake.message
        vnt_update_obj.add(stake.get_node())

    def validate(self, vnt: "VerificationNetTimeline"):
        timestamp = cur_time()

        self.signed_vnt_packet.validate_signatures()

        if self.signed_vnt_packet.signed_by_N0():
            return

        signed_stake = self.data.signed_stake

        if not self.signed_vnt_packet.signed_by(signed_stake.message.public_key):
            raise DialogueException("Invalid signatures for event")

        signed_stake.validate_signatures()
        if signed_stake.signed_by_N0():
            return

        if not signed_stake.signed_by(signed_stake.message.public_key):
            raise DialogueException("Invalid signatures for event")

        stake = signed_stake.message

        if stake.timestamp < timestamp - TIME_TO_CONSISTENCY:
            raise DialogueException(
                "Stake expired"
            )  # Prevents old stakes from being reused to join vnt

        stake.validate_funds(vnt, timestamp)
        for fund in stake.funds:
            validate_signature_count(fund.witnesses, self.signed_vnt_packet.signatures)

            for witness in fund.witnesses:
                if not signed_stake.signed_by(witness.public_key):
                    raise DialogueException("Invalid signatures for event")


@dataclass(frozen=True)
class LeaveData(VNTEventData):
    event_type: Literal[VerificationNetEventEnum.NODE_LEAVE]
    stake_id: UUID
    stake_witnesses: tuple[VerificationNodeData, ...]
    fund_ids: tuple[str, ...]
    timestamp: float
    node: VerificationNodeData


class LeaveEvent(VerificationNetEvent[LeaveData]):

    def __init__(self, data: LeaveData, vnt_event_packet: Signed[VNTEventPacket]):
        super().__init__(data, vnt_event_packet)

    @classmethod
    def event_type(cls):
        return VerificationNetEventEnum.NODE_LEAVE

    def update_verification_list(self, vnt_update_obj: VNTUpdateHelper):
        vnt_update_obj.remove(self.data.node)

    def validate(self, vnt: "VerificationNetTimeline"):
        self.signed_vnt_packet.validate_signatures()
        if self.signed_vnt_packet.signed_by_N0():
            return

        if not self.signed_vnt_packet.signed_by(self.data.node.public_key):
            raise DialogueException("Invalid signatures for event")


@dataclass(frozen=True)
class PauseData(VNTEventData):
    event_type: Literal[VerificationNetEventEnum.NODE_PAUSE]
    timestamp: float
    node: VerificationNodeData


class PauseEvent(VerificationNetEvent[PauseData]):

    def __init__(self, data: PauseData, vnt_event_packet: Signed[VNTEventPacket]):
        super().__init__(data, vnt_event_packet)

    @classmethod
    def event_type(cls):
        return VerificationNetEventEnum.NODE_PAUSE

    def update_verification_list(self, vnt_update_obj: VNTUpdateHelper):
        vnt_update_obj.pause_node(self.data.node)

    def validate(self, vnt: "VerificationNetTimeline"):
        self.signed_vnt_packet.validate_signatures()
        if self.signed_vnt_packet.signed_by_N0():
            return

        if not self.signed_vnt_packet.signed_by(self.data.node.public_key):
            raise DialogueException("Invalid signatures for event")


@dataclass(frozen=True)
class ResumeData(VNTEventData):
    event_type: Literal[VerificationNetEventEnum.NODE_RESUME]
    timestamp: float
    node: VerificationNodeData


class ResumeEvent(VerificationNetEvent[ResumeData]):

    def __init__(self, data: ResumeData, vnt_event_packet: Signed[VNTEventPacket]):
        super().__init__(data, vnt_event_packet)

    @classmethod
    def event_type(cls):
        return VerificationNetEventEnum.NODE_RESUME

    def update_verification_list(self, vnt_update_obj: VNTUpdateHelper):
        vnt_update_obj.resume_node(self.data.node)

    def validate(self, vnt: "VerificationNetTimeline"):
        self.signed_vnt_packet.validate_signatures()
        if self.signed_vnt_packet.signed_by_N0():
            return

        if not self.signed_vnt_packet.signed_by(self.data.node.public_key):
            raise DialogueException("Invalid signatures for event")


@dataclass(frozen=True)
class EntropyData(VNTEventData):
    event_type: Literal[VerificationNetEventEnum.ADD_ENTROPY]
    timestamp: float
    node: VerificationNodeData
    entropy: str


class EntropyEvent(VerificationNetEvent[EntropyData]):

    def __init__(self, data: EntropyData, vnt_event_packet: Signed[VNTEventPacket]):
        super().__init__(data, vnt_event_packet)

    @classmethod
    def event_type(cls):
        return VerificationNetEventEnum.ADD_ENTROPY

    def update_verification_list(self, vnt_update_obj: VNTUpdateHelper): ...

    def validate(self, vnt: "VerificationNetTimeline"):
        self.signed_vnt_packet.validate_signatures()
        if self.signed_vnt_packet.signed_by_N0():
            return

        if not self.signed_vnt_packet.signed_by(self.data.node.public_key):
            raise DialogueException("Invalid signatures for event")
