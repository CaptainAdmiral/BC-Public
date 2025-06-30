import itertools
from typing import TYPE_CHECKING, Optional

from network_emulator import network

if TYPE_CHECKING:
    from network_emulator.net_connection import NetConnection
    from protocol.protocols.abstract_protocol import AbstractProtocol


class Node[T: "AbstractProtocol"]:
    _address_gen = itertools.count()

    def __init__(self):
        self.address = next(self._address_gen)
        network.join(self)
        self.protocol: T
        self.active = True

    def set_protocol(self, protocol: T):
        self.protocol = protocol

    async def request_net_connection(self, address: int) -> "NetConnection":
        return await network.connect(self.address, address)

    def accept_net_connection(self, net_con: "NetConnection"):
        if self.protocol is None:
            return
        self.protocol.accept_net_connection(net_con)
