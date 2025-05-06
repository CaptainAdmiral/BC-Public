import itertools
import protocol
import net_connection as nc
import network

class Node():
    _address_gen = itertools.count()

    def __init__(self, protocol: protocol.AbstractProtocol):
        self.address = next(self._address_gen)
        self.protocol = protocol
        self.active = True
    
    async def request_net_connection(self, address: int) -> nc.NetConnection:
        return await network.connect(self.address, address)

    def accept_net_connection(self, net_con: nc.NetConnection):
        self.protocol.accept_net_connection(net_con)