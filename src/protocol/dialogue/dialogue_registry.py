import functools
import logging
from typing import TYPE_CHECKING, Callable, Concatenate, Coroutine

from protocol.dialogue.const import DialogueEnum
from protocol.dialogue.dialogue_types import DialogueException
from protocol.dialogue.util.dialogue_util import DialogueUtil
from settings import LOG_DIALOGUES

if TYPE_CHECKING:
    from protocol.protocols.abstract_protocol import AbstractProtocol

type DialogueType = Callable[Concatenate[DialogueUtil, AbstractProtocol, ...], Coroutine]

# fmt: off
def dialogue_registrars(dialogue_registry: dict[str, DialogueType], response_registry: dict[str, DialogueType]):
    """Returns a pair of decorators you can use to register your dialogues and responses with the passed registry objects.
    
    Returns:
        register_init, register_response"""
    
    def register_init(key: DialogueEnum):
        '''Registers an initial dialogue for use by your protocol.
        Modifies the decorated function to send a dialogue identifier first to initiate the dialogue.
        
        Decorator for an async function with signature (DialogueUtil, StdProtocol, *args, **kwargs)'''
        
        def deco[T: 'AbstractProtocol', R, **P](f: Callable[Concatenate[DialogueUtil, T, P], Coroutine[None, None, R]]):

            @functools.wraps(f)
            async def wrapped(du: DialogueUtil, protocol: T, *args: P.args, **kwargs: P.kwargs):
                if LOG_DIALOGUES:
                    logging.info(f"[{du.net_connection._node.address} | {du.net_connection._other_node.address}] Initiating dialogue: {key}")
                try:
                    du.init(key)
                    res = await f(du, protocol, *args, **kwargs)
                    if du._last_com_type == du.ComType.OUT:
                        await du.expect_acknowledgement()
                    return res
                except DialogueException as e:
                    e.add_note(f"Raised in init: {key} [{du.net_connection._node.address} | {du.net_connection._other_node.address}]")
                    du.error()
                    raise e
            
            dialogue_registry[key] = wrapped # type: ignore
            return wrapped
        return deco

    def register_response(key: DialogueEnum):
        '''Registers a dialogue response for use by your protocol.
        
        Decorator for an async function with signature (DialogueUtil, AbstractProtocol)'''

        def deco[T: 'AbstractProtocol', R](f: Callable[[DialogueUtil, T], Coroutine[None, None, R]]):

            @functools.wraps(f)
            async def wrapped(du: DialogueUtil, protocol: T):
                if LOG_DIALOGUES:
                    logging.info(f"[{du.net_connection._node.address} | {du.net_connection._other_node.address}] Responding to: {key}")
                try:
                    await du.expect(key)
                    res = await f(du, protocol)
                    if du._last_com_type == du.ComType.IN:
                        du.acknowledge()
                    return res
                except DialogueException as e:
                    e.add_note(f"Raised in response: {key} [{du.net_connection._node.address} | {du.net_connection._other_node.address}]")
                    du.error()
                    raise e
                            
            response_registry[key] = wrapped # type: ignore
            return wrapped
        return deco
    
    return register_init, register_response
# fmt: on


def validate_symetric_dialogues(Protocol: "type[AbstractProtocol]"):
    init_keys = Protocol.dialogues().keys()
    res_keys = Protocol.responses().keys()

    if init_keys != res_keys:
        missing = init_keys ^ res_keys
        raise ValueError(
            f"Missing registry entries for standard protocol. Missing initial or response dialogues for: {', '.join(missing)}"
        )
