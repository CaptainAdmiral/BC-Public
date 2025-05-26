from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Callable, Concatenate, Coroutine, cast

import async_manager
from network_emulator import network
from protocol.dialogue.const import ControlPacket, DialogueEnum
from protocol.dialogue.dialogue_types import DialogueException
from protocol.dialogue.util.dialogue_util import DialogueUtil

if TYPE_CHECKING:
    from network_emulator.net_connection import NetConnection
    from network_emulator.node import Node


class AbstractProtocol(ABC):

    def __init__(self, node: "Node"):
        self._node = node
        self.address = node.address

    def add_task(self, coro: Coroutine):
        async_manager.add_async_task(coro)

    @staticmethod
    @abstractmethod
    def weight() -> float:
        """The weight with which this protocol will be chosen to populate the network.

        The standard protocol has a weight of 1.0"""
        pass

    @classmethod
    @abstractmethod
    def dialogues(
        cls,
    ) -> dict[
        str, Callable[Concatenate[DialogueUtil, "AbstractProtocol", ...], Coroutine]
    ]: ...

    @classmethod
    @abstractmethod
    def responses(
        cls,
    ) -> dict[
        str, Callable[Concatenate[DialogueUtil, "AbstractProtocol", ...], Coroutine]
    ]: ...

    def get_dialogue(self, key: str):
        return self.dialogues()[key]

    async def _request_net_connection(self, address: int) -> "NetConnection":
        return await self._node.request_net_connection(address)

    def get_response(self, dialogue_key: DialogueEnum):
        """Get's the response for an incoming dialogue from the registry.
        Overwrite to add custom behavior for certain dialogue responses"""

        responses = self.responses()
        if dialogue_key not in responses:
            raise DialogueException(f"Unknown dialogue_key: {dialogue_key}")

        return responses[dialogue_key]

    async def _monitor_net_connection(self, net_con: "NetConnection"):
        with net_con:
            while net_con.is_open:
                du = DialogueUtil(net_con)
                try:
                    dialogue_key_str = await net_con.peak()
                    assert dialogue_key_str is not None
                    dialogue_key_str = dialogue_key_str[1:-1] # Strip quotes
                    dialogue_key = cast(DialogueEnum, dialogue_key_str)
                    dialogue = self.get_response(dialogue_key)
                    await dialogue(du, self)
                except DialogueException as e:
                    du.error()
                    raise(e)
                    
    def accept_net_connection(self, net_con: "NetConnection"):
        """Accepts an incoming net connection"""
        self.add_task(self._monitor_net_connection(net_con))

    async def run_dialogue(self, address: int, dialogue: DialogueEnum, *args, **kwargs):
        nc = await network.connect(self.address, address)
        with nc:
            du = DialogueUtil(nc)
            await self.get_dialogue(dialogue)(du, self, *args, **kwargs)
