from types import NoneType
from typing import Callable
from protocol.abstract_protocol import AbstractProtocol
from protocol.dialogue.const import ControlPacket
from protocol.dialogue.dialogue_graph import DataType, DialogueGraph, DialogueInfo
from protocol.dialogue.const import DialogueEnum
from protocol.std_protocol.std_protocol import StdProtocol

class DialogueGraphWrapper[A, P: AbstractProtocol, T1, T2, R1, R2]:

    def __init__(self, initial: DialogueGraph[A, P, T1, R1], response: DialogueGraph[NoneType, P, T2, R2]):
        self._initial = initial
        self._response = response

    def initial(self):
        return self._initial
    
    def response(self):
        return self._response

class DialogueBuilder[A, P: AbstractProtocol, T1, T2, R1, R2]:
    
    def __init__(self,
                 key: DialogueEnum,
                 *,
                 Args: type[A] = NoneType,
                 InitialStateType: type[T1] = NoneType,
                 ResponseStateType: type[T2] = NoneType,
                 Protocol: type[P] = StdProtocol,
                 InitialReturnType: type[R1] = NoneType,
                 ResponseReturnType: type[R2] = NoneType):
        self.key = key
        self._Args = Args
        self.StateInitial = InitialStateType
        self.StateResponse = ResponseStateType
        self.Protocol = Protocol
        self.ReturnTypeInitial = InitialReturnType
        self.ReturnTypeResponse = ResponseReturnType
        self._initial: DialogueGraph[A, P, T1, R1]
        self._response: DialogueGraph[None, P, T2, R2]

    def build_initial(self):
        self._initial = DialogueGraph[A, P, T1, R1](self.key, self._Args, self.StateInitial, self.Protocol, ReturnType=self.ReturnTypeInitial)
        return self._initial.initiate()
    
    def build_response(self, reply: DataType | Callable[[str, DialogueInfo[None, P, T2]]] = ControlPacket.ACKNOWLEDGEMENT):
        self._response = DialogueGraph[None, P, T2, R2](self.key, NoneType, self.StateResponse, self.Protocol, ReturnType=self.ReturnTypeResponse)
        return self._response.reply(reply)
    
    def dialogues(self):
        return DialogueGraphWrapper(initial=self._initial, response=self._response)