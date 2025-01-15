import itertools
from typing import Self
import protocol
import net_connection as nc
import network

class Node():
    _address_gen = itertools.count()

    def __init__(self, protocol: protocol.AbstractProtocol):
        self.address = next(self._address_gen)
        self.protocol = protocol
    
    async def request_net_connection(self, other: Self) -> nc.NetConnection:
        return await network.connect_to_node(self, other)

    def accept_net_connection(self, net_con: nc.NetConnection):
        self.protocol.accept_net_connection(net_con)