from typing import Callable, Iterable, Optional
from protocol.std_protocol.std_protocol import VerificationNodeData
from protocol.verification_net.verification_net_event import VerificationNetEvent
from util.chronology import _Event, Chronology

class VerificationNetTimeline(Chronology[VerificationNetEvent]):
    '''Collection to automatically sort and rehash validation events by timestamp'''

    def __init__(self, iterable: Optional[Iterable[VerificationNetEvent]] = None, *, epoch_length: Optional[float] = None, key: Optional[Callable[[VerificationNetEvent], float]] = None):
        super().__init__(iterable, epoch_length=epoch_length, key=key)
        self._hash_dict: dict[int, _Event[VerificationNetEvent]] = {}

    def add(self, event: VerificationNetEvent):
        event.validate() # Will raise an exception if validation fails

        node = super().add(event)
        assert(node)

        # Update each of the subsequent event's hashes using its own data and the previous event's hash
        last_hash = node.data.checksum
        for event in self.iter_from(node):
            node.data.prev_hash = last_hash
            node.data.update_checksum()
            last_hash = node.data.checksum
        
        self._hash_dict[event.checksum] = node
        return node
    
    def get_hash(self, hash: int):
        if hash in self._hash_dict:
            return self._hash_dict[hash]
        return None
    
    def __contains__(self, item):
        if not isinstance(item, int):
            return False
        return item in self._hash_dict
    
    def to_list(self, cutoff: Optional[float]=None) -> list[VerificationNodeData]:
        '''Iterates the timeline and builds the resultant list from the event data'''

        selected_nodes: list[VerificationNodeData] = []
        for event in self.bounded_iter(None, cutoff):
            event.update_verification_list(selected_nodes)
        return selected_nodes
    
    def get_random_seed(self, cutoff: Optional[float]=None):
        """Get's a random seed from the entropy produced by the VNT at time 'cutoff'"""
        
        latest = self.latest_before(cutoff)
        
        if latest is None:
            raise ValueError('Calling get_random_seed on empty timeline is not allowed')
        
        return latest.checksum