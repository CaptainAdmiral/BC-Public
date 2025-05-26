from typing import Any
from pydantic import TypeAdapter

from crypto.signature import Signed
from protocol.verification_net.vnt_types import (
    EntropyData,
    EntropyEvent,
    JoinData,
    JoinEvent,
    LeaveData,
    LeaveEvent,
    PauseData,
    PauseEvent,
    ResumeData,
    ResumeEvent,
    VerificationNetEvent,
    VerificationNetEventEnum,
    VNTEventPacket,
)
from util.type_adapters import get_type_adapter

type VNTEventDataTypes = JoinData | LeaveData | PauseData | ResumeData | EntropyData


class VNTEventFactory:
    vntEvents: list[type[VerificationNetEvent]] = [
        JoinEvent,
        LeaveEvent,
        PauseEvent,
        ResumeEvent,
        EntropyEvent,
    ]

    @classmethod
    def event_from_packet(
        cls, signed_packet: Signed[VNTEventPacket]
    ) -> VerificationNetEvent:
        adapter = None
        match signed_packet.message.event_type:
            case VerificationNetEventEnum.NODE_JOIN:
                adapter = get_type_adapter(JoinData)
            case VerificationNetEventEnum.NODE_LEAVE:
                adapter = get_type_adapter(LeaveData)
            case VerificationNetEventEnum.NODE_PAUSE:
                adapter = get_type_adapter(PauseData)
            case VerificationNetEventEnum.NODE_RESUME:
                adapter = get_type_adapter(ResumeData)
            case VerificationNetEventEnum.ADD_ENTROPY:
                adapter = get_type_adapter(EntropyData)
            case _:
                raise NotImplementedError()

        data = adapter.validate_json(signed_packet.message.data)
        return next(
            t for t in cls.vntEvents if t.event_type() == signed_packet.message.event_type
        )(data, signed_packet)

    @classmethod
    def packet_from_data(
        cls, event_type: VerificationNetEventEnum, data: VNTEventDataTypes
    ):
        data_str = get_type_adapter(Any).dump_json(data).decode("utf-8")
        return VNTEventPacket(event_type, data_str)
