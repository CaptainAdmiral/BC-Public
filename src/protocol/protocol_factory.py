import numpy as np
from numpy import random

from protocol.protocols.abstract_protocol import AbstractProtocol

_type_set: set[type[AbstractProtocol]] = set()
_type_array = np.array(_type_set)
_weights = np.array([Protocol.weight() for Protocol in _type_set])

def register_protocol(*protocols: type[AbstractProtocol]) -> None:
    '''Registers a protocol so that it will be randomly used by nodes in the network according to weight'''

    global _type_set, _type_array, _weights

    for protocol in protocols:
        _type_set.add(protocol)
    
    _type_array = np.array(_type_set)
    _weights = np.array([Protocol.weight() for Protocol in _type_set])

def get_protocol(node) -> AbstractProtocol:
    return random.choice(_type_array, p=_weights)(node)