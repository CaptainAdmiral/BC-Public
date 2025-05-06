import functools
from typing import Callable, Concatenate, Coroutine
from protocol.dialogue.base_dialogue import DialogueException
from protocol.dialogue.broadcast import Broadcast
from protocol.dialogue.const import ControlPacket, DialogueEnum
from protocol.dialogue.util.dialogue_util import DialogueUtil
from protocol.std_protocol.std_protocol import StdProtocol

DialogueType = Callable[Concatenate[DialogueUtil, StdProtocol, ...], Coroutine]

_INIT_REGISTRY: dict[str, DialogueType] = {}
RESPONSE_REGISTRY: dict[str, DialogueType] = {}

BROADCAST_REGISTRY: dict[str, Broadcast] = {}

def register_init(key: DialogueEnum):
    '''Registers an initial dialogue for use by the standard protocol.
    Modifies the decorated function to send a dialogue identifier first to initiate the dialogue.
    This was designed as a convenience function for internal use only, nodes running deviant protocols should not register their dialogues with the standard protocol
    
    Decorator for an async function with signature (DialogueUtil, StdProtocol, *args, **kwargs)'''
    
    def deco[R, **P](f: Callable[Concatenate[DialogueUtil, StdProtocol, P], Coroutine[None, None, R]]):
        _INIT_REGISTRY[key] = f

        @functools.wraps(f)
        async def wrapped(du: DialogueUtil, protocol: StdProtocol, *args: P.args, **kwargs: P.kwargs):
            try:
                du.init(key)
                return await f(du, protocol, *args, **kwargs)
            except DialogueException as e:
                du.reply(ControlPacket.ERROR)
                raise e
        
        return wrapped
    return deco

def register_response(key: DialogueEnum):
    '''Registers a dialogue response for use by the standard protocol. This was designed as a convenience function for internal use only,
    nodes running deviant protocols should not register their dialogues with the standard protocol
    
    Decorator for an async function with signature (DialogueUtil, StdProtocol)
    The decorated function my also take net_con as a keyword argument, which will receive the same NetConnection reference used by DialogueUtil'''

    def deco[R](f: Callable[[DialogueUtil, StdProtocol], Coroutine[None, None, R]]) -> Callable[[DialogueUtil, StdProtocol], Coroutine[None, None, R]]:
        RESPONSE_REGISTRY[key] = f

        @functools.wraps(f)
        async def wrapped(du: DialogueUtil, protocol: StdProtocol):
            try:
                await du.expect(key)
                return await f(du, protocol)
            except DialogueException as e:
                du.reply(ControlPacket.ERROR)
                raise e
                           
        return wrapped
    return deco

def register_broadcast(broadcast: Broadcast):
    '''Registers a broadcast for use by the standard protocol. This was designed as a convenience function for internal use only,
    nodes running deviant protocols should not register their broadcasts with the standard protocol'''

    BROADCAST_REGISTRY[broadcast.key] = broadcast

def get_response(key: DialogueEnum):
    if key in RESPONSE_REGISTRY:
        return RESPONSE_REGISTRY[key]
    elif key in BROADCAST_REGISTRY:
        return BROADCAST_REGISTRY[key]
    else:
        raise DialogueException(f"Unknown dialogue key: {key}")
    
def validate_registries():
    init_keys = _INIT_REGISTRY.keys()
    res_keys = RESPONSE_REGISTRY.keys()
    b_keys = BROADCAST_REGISTRY.keys()
    
    if init_keys != res_keys:
        missing = init_keys ^ res_keys
        raise ValueError(f"Missing registry entries for standard protocol. Missing initial or response dialogues for: {', '.join(missing)}")
    
    if (intersection := b_keys & res_keys):
        raise ValueError(f"Duplicate registry entries for standard protocol. The following keys were found in both broadcasts and dialogue registries: {', '.join(intersection)}")