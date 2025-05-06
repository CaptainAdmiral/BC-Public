from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import cast
from network_emulator import NetConnection
from protocol.abstract_protocol import AbstractProtocol
from protocol.dialogue.const import DialogueEnum

class DialogueException(Exception):
    '''Exception with execution of dialogue'''
    ...

@dataclass
class DialogueResult[R]:
    exception: Exception | None
    success: bool
    result: R | None = None

    def __bool__(self):
        if not self.success:
            return False
        return bool(self.result)
    
    def assumed_result(self) -> R:
        '''Gets the result assuming the dialogue was successful. (Casts out the None from the result type union)'''
        return cast(R, self.result)

class BaseDialogue[R](ABC):

    @abstractmethod
    def key(self) -> DialogueEnum:
        ...

    @abstractmethod
    async def execute(self, protocol: AbstractProtocol, net_con: NetConnection) -> R | None:
        ...

    async def run(self, protocol: AbstractProtocol, net_con: NetConnection) -> DialogueResult[R]:
        if not net_con.is_open:
            raise NetConnection.NetConnectionClosedException('Net connection must be opened first')

        result = None
        exception = None
        try:
            result = await self.execute(protocol, net_con)
        except DialogueException as e:
            exception = e

        return DialogueResult(success=exception is None, exception=exception, result=result)