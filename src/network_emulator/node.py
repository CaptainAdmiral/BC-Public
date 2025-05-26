from enum import Enum, auto
import itertools
from typing import TYPE_CHECKING
from network_emulator import network
from protocol import protocol_factory
from protocol import StdProtocol
from protocol import ZeroProtocol

if TYPE_CHECKING:
    from protocol.protocols.abstract_protocol import AbstractProtocol
    from network_emulator.net_connection import NetConnection

class ProtocolSelectionBehaviour(Enum):
    SELECT_RANDOM = auto()
    USE_STD = auto()
    USE_ZERO = auto()
    NO_PROTOCOL = auto()

class Node:
    _address_gen = itertools.count()

    def __init__(self, protocol_selection: ProtocolSelectionBehaviour=ProtocolSelectionBehaviour.SELECT_RANDOM):
        self.address = next(self._address_gen)
        network.join(self)
        self.protocol: 'AbstractProtocol | None'
        match protocol_selection:
            case ProtocolSelectionBehaviour.SELECT_RANDOM:
                self.protocol = protocol_factory.get_protocol(self)
            case ProtocolSelectionBehaviour.USE_STD:
                self.protocol = StdProtocol(self)
            case ProtocolSelectionBehaviour.USE_ZERO:
                self.protocol = ZeroProtocol(self)
            case ProtocolSelectionBehaviour.NO_PROTOCOL:
                self.protocol = None
            case _:
                raise NotImplementedError()
        self.active = True
    
    def set_protocol(self, protocol: 'AbstractProtocol'):
        self.protocol = protocol

    async def request_net_connection(self, address: int) -> 'NetConnection':
        return await network.connect(self.address, address)

    def accept_net_connection(self, net_con: 'NetConnection'):
        if self.protocol is None:
            return
        self.protocol.accept_net_connection(net_con)
