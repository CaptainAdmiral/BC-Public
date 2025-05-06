from dataclasses import dataclass
from types import NoneType
from typing import Any, Awaitable, Callable, Optional, Self, cast, override
from abc import ABC, abstractmethod
from network_emulator import NetConnection
from protocol.abstract_protocol import AbstractProtocol
from protocol.dialogue.base_dialogue import BaseDialogue, DialogueException, DialogueResult
from protocol.dialogue.const import ControlPacket
from protocol.dialogue.util.dialogue_util import DialogueUtil, DataType
from protocol.dialogue.const import DialogueEnum
from protocol.std_protocol.std_protocol import StdProtocol
from util.documentation import get_referenced

class DialogueGraphException(Exception):
    '''Exception when building dialogue graph'''
    ...

@dataclass
class DialogueInfo[A, P: AbstractProtocol, T]:
    args: A
    protocol: P
    state: T

class DialogueGraph[A, P: AbstractProtocol, T, R]:

    def __init__(self, key: DialogueEnum, Args: type[A] = NoneType, State: type[T] = NoneType, Protocol: type[P] = StdProtocol, *, ReturnType: type[R] = NoneType):
        self.key = key
        self._Protocol = Protocol
        self.dialogue: _Reply[str, A, P, T, R]
        self._State = State
        self._Args = Args

    @property
    def Protocol(self):
        return self._Protocol
    
    async def execute(self, net_con: NetConnection, info: DialogueInfo[A, P, T]) -> R | None:
        '''Parses the dialogue graph and executes communication via the net connection'''

        node = self.dialogue
        data = None
        
        while node is not None:
            data = await node.execute(net_con, data, info)
            
            for action in node.actions:
                res = action(data, info)
                if isinstance(res, Awaitable):
                    res = await res
            
            if isinstance(node, _Result):
                return data
            else:
                node = node.get_next_node(data, info)

        return None
    
    def initial_args(self, *args, **kwargs) -> A:
        return self._Args(*args, **kwargs)
    
    def initial_state(self) -> T:
        return self._State()
    
    def initiate(self):
        '''Initializes the root of the dialogue tree with a reply node sending the dialogue key'''
        self.dialogue = _Reply[str, A, P, T, R](self.key)
        return self.dialogue
    
    def reply(self, reply: DataType | Callable[[str, DialogueInfo[A, P, T]]]):
        '''Initializes the root of the dialogue tree with a reply node acknowledging the dialogue key'''
        self.dialogue = _Reply[str, A, P, T, R](reply)
        return self.dialogue
    
class _AbstractDialogueStep[D, A, P: AbstractProtocol, T, R](ABC):

    def __init__(self):
        self._child: Optional[_AbstractDialogueStep] = None
        self.actions: list[Callable[[D, DialogueInfo[A, P, T]]]] = []

    def get_children(self) -> list['_AbstractDialogueStep[Any, A, P, T, R] | None']:
        return [self._child]
    
    def get_next_node(self, data: D, state: DialogueInfo[A, P, T]) -> '_AbstractDialogueStep[Any, A, P, T, R] | None':
        return self._child
    
    def do(self, action: Callable[[D, DialogueInfo[A, P, T]], Awaitable[None] | Any], /, annotation: Optional[str]=None) -> Self:
        '''Executes a callback after this node executes successfully.
        This does not add a new node to the dialogue tree.'''
        self.actions.append(action)
        return self
    
    @abstractmethod
    async def execute(self, net_connection: NetConnection, data: D | None, info: DialogueInfo[A, P, T]) -> Any:
        ...

class _Fail[A, P: AbstractProtocol, T, R](_AbstractDialogueStep[Any, A, P, T, R]):

    def __init__(self, message: Optional[str] = 'Dialogue Failed'):
        super().__init__()
        self.message = message
    
    @override
    async def execute(self, net_connection, data, info):
        raise DialogueException(self.message)

class _InternalMixin[D, A, P: AbstractProtocol, T, R1]:

    def join(self, node: _AbstractDialogueStep) -> _AbstractDialogueStep[Any, A, P, T, R1]:
        '''Extends the dialogue graph at this node by taking the given node as a child
        
        Args:
            node: the node to join as a child of this one
        Returns:
            node (for method chaining)
        '''
        self._child = node
        return self._child
    
    async def functional[R2](self, func: Callable[[D | None, _Functional, DialogueUtil, DialogueInfo[A, P, T]], Awaitable[R2]]) -> '_Functional[D, A, P, T, R2, R1]':
        '''Allows use of traditional async await code blocks to handle dialogue that requires more complex program control structures'''

        self._child = _Functional(func)
        return self._child
    
    def fail(self, message: str):
        '''Causes the dialogue to raise an exception'''

        self._child = _Fail[A, P, T, R1](message)
        return self._child
    
    def dialogue[R2](self, dialogue: BaseDialogue[R2] | Callable[[D, DialogueInfo[A, P, T]], BaseDialogue[R2]], /, annotation: Optional[str]=None, reraise_exceptions=True) -> _Dialogue[D, A, P, T, R1, R2]:
        self._child = _Dialogue[D, A, P, T, R1, R2](dialogue, reraise_exceptions=reraise_exceptions)
        return self._child
    
    def result(self, result: R1 | Callable[[D, DialogueInfo[A, P, T]], R1], /, annotation: Optional[str]=None) -> '_Result[D, A, P, T, R1]':
        self._child = _Result[D, A, P, T, R1](result)
        return self._child
    
class _Fork[D, A, P: AbstractProtocol, T, R](_AbstractDialogueStep[D, A, P, T, R]):

    def __init__(self):
        super().__init__()
        self._children: list[Any] = []
    
    @override
    @abstractmethod
    def get_next_node(self, data: D, state: DialogueInfo[A, P, T]) -> '_AbstractDialogueStep[Any, A, P, T, R] | None':
        pass
    
    @override
    async def execute(self, net_connection: NetConnection, data: D | None, info: DialogueInfo[A, P, T]) -> D:
        assert(data is not None)
        return data
    
class _ForkReplies[D, A, P: AbstractProtocol, T, R](_Fork[D, A, P, T, R]):
    
    def __init__(self):
        self._children: list[tuple[Callable[[D, DialogueInfo[A, P, T]], bool], _AbstractDialogueStep]]
        self._default_child: _AbstractDialogueStep | None = None
        super().__init__()

    @override
    def get_next_node(self, data: D, state: DialogueInfo[A, P, T]) -> '_AbstractDialogueStep[Any, A, P, T, R] | None':
        child = None
        for f, child_candidate in self._children:
            if f(data, state):
                child = child_candidate
                break
        else:
            if self._default_child is not None:
                child = self._default_child
            else:
                return None
        
        self._child = child
        return self._child
    
    def result_if(self, condition: Callable[[D, DialogueInfo[A, P, T]]], result: R | Callable[[D, DialogueInfo[A, P, T]], R], /, annotation: Optional[str]=None):
        '''New dialogue branch if condition is met'''
        child = _Result[D, A, P, T, R](result)
        self._children.append((condition, child))
        return child
    
    def result_default(self, result: R | Callable[[D, DialogueInfo[A, P, T]], R], /, annotation: Optional[str]=None):
        child = _Result[D, A, P, T, R](result)
        self._default_child = child
        return child

    def reply_if(self, condition: Callable[[D, DialogueInfo[A, P, T]]], identifier: str, /, annotation: Optional[str]=None):
        '''New dialogue branch if condition is met'''
        child = _Reply[D, A, P, T, R](identifier)
        self._children.append((condition, child))
        return child
    
    def reply_default(self, identifier, /, annotation: Optional[str]=None):
        child = _Reply[D, A, P, T, R](identifier)
        self._default_child = child
        return child
    
    def fail_if(self, condition: Callable[[D, DialogueInfo[A, P, T]]], message: Optional[str]='Dialogue Failed', /, annotation: Optional[str]=None):
        child = _Fail[A, P, T, R](message)
        self._children.append((condition, child))
        return child
    
    def fail_default(self, message: Optional[str]='Dialogue Failed', /, annotation: Optional[str]=None):
        child = _Fail[A, P, T, R](message)
        self._default_child = child
        return child
    
class _ExpectFork[D, A, P: AbstractProtocol, T, R](_Fork[D, A, P, T, R]):
    
    def __init__(self):
        self._children: list[_Expect]
        super().__init__()

    @override
    def get_next_node(self, data: D, state: DialogueInfo[A, P, T]) -> '_AbstractDialogueStep[Any, A, P, T, R] | None':
        child = None
        for child_candidate in self._children:
            if data == child_candidate._expect:
                child = child_candidate
                break
        else:
            raise DialogueException('No matching child for fork')
        
        self._child = child
        return self._child
    
    def expect(self, identifier: str, /, annotation: Optional[str]=None):
        '''New dialogue branch from fork'''
        rep = _Expect[str, A, P, T, R](identifier)
        self._children.append(rep)
        return rep
    
class _ReplyMixin[D, A, P: AbstractProtocol, T, R](_InternalMixin[D, A, P, T, R]):

    def expect[E: DataType](self, expect: E | type[E], /, annotation: Optional[str]=None, *, unmet: Callable | None = None) -> _Expect[E, A, P, T, R]:
        '''Validates that the incoming data is correctly formatted.

        Args:
            unmet: Callback for if the expectation is not met'''

        self._child = _Expect[E, A, P, T, R](expect, unmet=unmet)
        return self._child

    def expect_acknowledgement(self):
        '''Expects an acknowledgement packet'''
        return self.expect(ControlPacket.ACKNOWLEDGEMENT)
    
    def expect_fork(self) -> _ExpectFork[D, A, P, T, R]:
        '''Forks the dialogue graph. Only the child with matching identifier will be used at runtime.'''

        self._child = _ExpectFork[D, A, P, T, R]()
        return self._child

class _Reply[D, A, P: AbstractProtocol, T, R](_ReplyMixin[D, A, P, T, R], _AbstractDialogueStep[D, A, P, T, R]):     

    def __init__(self, reply: DataType | Callable[[D, DialogueInfo[A, P, T]], Any]):
        super().__init__()
        self._child = None
        self._reply = reply
    
    @override
    async def execute(self, net_connection: NetConnection, data: Any, info: DialogueInfo[A, P, T]) -> Any:
        du = DialogueUtil(net_connection)
        rep = self._reply
        if isinstance(self._reply, Callable):
            rep = self._reply(data, info)
        du.reply(rep)
        return data
    
class _Result[D, A, P: AbstractProtocol, T, R](_AbstractDialogueStep[D, A, P, T, R]):

    def __init__(self, result: R | Callable[[D, DialogueInfo[A, P, T]], R]):
        super().__init__()
        self._result = result
    
    @override
    async def execute(self, net_connection: NetConnection, data: D | None, info: DialogueInfo[A, P, T]) -> R:
        if isinstance(self._result, Callable):
            return self._result(cast(D, data), info)
        else:
            return self._result

class _ExpectMixin[D: DataType, A, P: AbstractProtocol, T, R](_InternalMixin[D, A, P, T, R]):
        
    def reply(self, reply: DataType | Callable[[D, DialogueInfo[A, P, T]], Any], /, annotation: Optional[str]=None) -> _Reply[D, A, P, T, R]:
        '''Sends a reply packet'''

        self._child = _Reply[D, A, P, T, R](reply)
        return self._child

    def acknowledge(self):
        '''Sends an acknowledgement packet'''
        return self.reply(ControlPacket.ACKNOWLEDGEMENT)
    
    def fork_replies(self) -> _ForkReplies[D, A, P, T, R]:
        '''Forks the dialogue graph. The first child with matching condition will be used at runtime.'''

        self._child = _ForkReplies[D, A, P, T, R]()
        return self._child
    
    def validate(self, validator: Callable[[D, DialogueInfo[A, P, T]], bool], /, annotation: Optional[str]=None) -> Self:
        '''Accepts a callback to perform further validation of the data.
        If the callback returns False an exception is raised.
        
        This does not add a new node to the dialogue tree.'''

        if not hasattr(self, '_validators'):
            self._validators: list[Callable[[D, DialogueInfo[A, P, T]], bool]] = []
        self._validators.append(validator)
        return self

class _Expect[D: DataType, A, P: AbstractProtocol, T, R](_ExpectMixin[D, A, P, T, R], _AbstractDialogueStep[D, A, P, T, R]):

    def __init__(self, expect: D | type[D], *, unmet: Callable | None = None):
        super().__init__()
        self._expect = expect
        self._err_func = unmet
        self._data: Any = None
    
    @override
    async def execute(self, net_connection: NetConnection, data: Any, info: DialogueInfo[A, P, T]) -> D:
        du = DialogueUtil(net_connection)
        processed_data = await du.expect(self._expect)
        
        for validator in self._validators:
            if not validator(processed_data, info):
                raise DialogueException('Validation Failed')
        
        return processed_data
    
class _Functional[D, A, P: AbstractProtocol, T, R1: DataType | Any, R2](_ReplyMixin[R1, A, P, T, R2], _ExpectMixin[R1, A, P, T, R2], _AbstractDialogueStep[D, A, P, T, R2]):

    def __init__(self, func: Callable[[D | None, Self, DialogueUtil, DialogueInfo[A, P, T]], Awaitable[R1]]):
        super().__init__()
        self._func = func
        self._children = get_referenced(func, _AbstractDialogueStep)

    def set_child(self, child: _AbstractDialogueStep):
        self._child = child

    @override
    async def execute(self, net_connection: NetConnection, data: D | None, info: DialogueInfo[A, P, T]) -> R1:
        du = DialogueUtil(net_connection)
        return await self._func(data, self, du, info)

class _Dialogue[D, A, P: AbstractProtocol, T, R1, R2: DataType | Any](_ReplyMixin[DialogueResult[R2], A, P, T, R1], _ExpectMixin[DialogueResult[R2], A, P, T, R1], _AbstractDialogueStep[DialogueResult[R2], A, P, T, R1]):
    
    def __init__(self, dialogue: BaseDialogue[R2] | Callable[[D, DialogueInfo[A, P, T]], BaseDialogue[R2]], reraise_exceptions=True):
        super().__init__()
        self._dialogue = dialogue
        self.reraise_exceptions = reraise_exceptions

    @override
    async def execute(self, net_connection: NetConnection, data: Any, info: DialogueInfo[A, P, T]) -> DialogueResult[R2]:
        if isinstance(self._dialogue, Callable):
            dialogue = self._dialogue(cast(D, data), info)
        else:
            dialogue = self._dialogue

        result = await dialogue.run(info.protocol, net_connection)
        if self.reraise_exceptions and result.exception is not None:
            raise result.exception
        return result