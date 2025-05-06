from abc import ABC, abstractmethod
from typing import Coroutine
import async_manager
import network_emulator as ne

class AbstractProtocol(ABC):

    def __init__(self, node: ne.Node):
        self._node = node

    def add_task(self, coro: Coroutine):
        async_manager.add_async_task(coro)
    
    @staticmethod
    @abstractmethod
    def weight() -> float:
        '''The weight with which this protocol will be chosen to populate the network.
        
        The standard protocol has a weight of 1.0'''
        pass

    async def _request_net_connection(self, address: int) -> ne.NetConnection:
        return await self._node.request_net_connection(address)

    @abstractmethod
    def accept_net_connection(self, net_con: ne.NetConnection):
        pass