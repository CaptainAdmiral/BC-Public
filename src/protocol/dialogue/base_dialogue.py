from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast
from protocol.dialogue.const import DialogueEnum
from protocol.dialogue.dialogue_types import DialogueException, DialogueResult

if TYPE_CHECKING:
    from network_emulator.net_connection import NetConnection
    from protocol.protocols.abstract_protocol import AbstractProtocol

class BaseDialogue[R](ABC):

    @abstractmethod
    def key(self) -> DialogueEnum:
        ...

    @abstractmethod
    async def execute(self, protocol: 'AbstractProtocol', net_con: 'NetConnection') -> R | None:
        ...

    async def run(self, protocol: 'AbstractProtocol', net_con: 'NetConnection') -> DialogueResult[R]:
        if not net_con.is_open:
            raise NetConnection.NetConnectionClosedException('Net connection must be opened first')

        result = None
        exception = None
        try:
            result = await self.execute(protocol, net_con)
        except DialogueException as e:
            exception = e

        return DialogueResult(success=exception is None, exception=exception, result=result)