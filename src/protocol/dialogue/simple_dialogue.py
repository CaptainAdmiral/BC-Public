from typing import Any, override
from network_emulator import NetConnection
from protocol.abstract_protocol import AbstractProtocol
from protocol.dialogue.base_dialogue import BaseDialogue
from protocol.dialogue.dialogue_graph import DialogueGraph, DialogueInfo
from protocol.dialogue.const import DialogueEnum

class SimpleDialogue[R](BaseDialogue[R]):

    def __init__(self, graph: DialogueGraph[Any, Any, Any, R], *args, **kwargs):
        self.graph = graph
        self.args = args
        self.kwargs = kwargs

    @override
    def key(self) -> DialogueEnum:
        return self.graph.key

    @override
    async def execute(self, protocol: AbstractProtocol, net_con: NetConnection) -> R | None:
        state = self.graph.initial_state()
        iargs = self.graph.initial_args(*self.args, **self.kwargs)
        info = DialogueInfo(protocol=protocol, state=state, args=iargs)

        return await self.graph.execute(net_con, info)
    
class DialogueWrapper:

    def __init__(self):
        raise NotImplementedError
    
    def __new__(cls):
        raise NotImplementedError

    @classmethod
    def initial(cls, *args, **kwargs) -> SimpleDialogue:
        raise NotImplementedError
    
    @classmethod
    def response(cls) -> SimpleDialogue:
        raise NotImplementedError