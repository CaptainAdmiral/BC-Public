import json
from typing import Any
from cryptography.signature import Signed
from protocol.verification_net.vnt_types import EntropyEvent, JoinEvent, LeaveEvent, PauseEvent, ResumeEvent, VNTEventPacket, VerificationNetEvent, VerificationNetEventEnum

class VNTEventFactory:
    vntEvents: list[type[VerificationNetEvent]] = [JoinEvent, LeaveEvent, PauseEvent, ResumeEvent, EntropyEvent]

    @classmethod
    def event_from_packet(cls, signed_packet: Signed[VNTEventPacket]) -> VerificationNetEvent:
        return next(t for t in cls.vntEvents if t.event_type == signed_packet.message.event_type)(signed_packet.message.data, signed_packet)

    @classmethod 
    def packet_from_data(cls, event_type: VerificationNetEventEnum, data: Any):
        return VNTEventPacket(event_type, json.dumps(data))
