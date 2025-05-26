import json
from typing import TYPE_CHECKING, Any, Callable

from pydantic import BaseModel

if TYPE_CHECKING:
    from protocol import AbstractProtocol

class BroadcastData(BaseModel):
    rebroadcast_probability: float
    origin_time: float
    visited: list[int]
    data: Any
    hash: int

    def __eq__(self, other):
        return isinstance(other, BroadcastData) and self.hash == other.hash
    
    def __hash__(self):
        return self.hash

class Broadcast[P: 'AbstractProtocol', T: BroadcastData]:
    '''Base broadcast class.
    
    Broadcasts distribute data to every node on the network using a decentralized broadcast protocol'''
    
    def __init__(self, key: str, on_received: Callable[[T, P], Any], DataType: type[T]):
        self.key = key
        self._on_received = on_received
        self.DataType = DataType

    def parse_data(self, data_str: str) -> T:
        data_dict: dict = json.loads(data_str)
        return self.DataType(**data_dict)
    
    def execute(self, data: T, protocol: P):
        self._on_received(data, protocol)