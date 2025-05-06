from typing import Iterable, Optional
from protocol.std_protocol.std_protocol import VerificationNodeData
from protocol.verification_net.verification_net_event import VerificationNetEvent
from util.chronology import _Event, Chronology

class VerificationNetTimeline(Chronology[VerificationNetEvent]):
    '''Collection to automatically sort and rehash validation events by timestamp'''

    def __init__(self, iterable: Optional[Iterable[VerificationNetEvent]] = None, *, epoch_length: Optional[float] = None):
        def secondary_sort(event: VerificationNetEvent):
            return event.id
        
        super().__init__(iterable, epoch_length=epoch_length, secondary_sort=secondary_sort)
        self._checksum_dict: dict[str, _Event[VerificationNetEvent]] = {} # dict[event_checksum, event]
        self._event_dict: dict[str, _Event[VerificationNetEvent]] = {} # dict[event_hash, event] TODO update with new events like _hash_dict

    def _update_checksums_from(self, node: _Event[VerificationNetEvent]):
        '''Update each of the subsequent event's hashes using its own data and the previous event's hash'''

        last_hash = node.data.prev_hash
        for event in self.wrapped_iter_from(node):
            del self._checksum_dict[event.data.checksum]
            event.data.prev_hash = last_hash
            event.data.update_checksum()
            self._checksum_dict[event.data.checksum] = event
            last_hash = event.data.checksum

    def _add(self, event: VerificationNetEvent):
        event.validate() # Will raise an exception if validation fails
        node = super().add(event)
        self._checksum_dict[event.checksum] = node
        self._event_dict[str(hash(event))] = node
        return node
    
    def add_all(self, events: Iterable[VerificationNetEvent]):
        earliest_node: _Event[VerificationNetEvent] | None = None
        for event in events:
            node = self.add(event)
            if earliest_node is None or node.timestamp < earliest_node.timestamp:
                earliest_node = node
        
        if earliest_node is not None:
            self._update_checksums_from(earliest_node)
        
    def from_checksum(self, checksum: str):
        if checksum in self._checksum_dict:
            return self._checksum_dict[checksum]
        return None
    
    def includes_checksum(self, checksum: str):
        return checksum in self._checksum_dict
    
    def includes_event(self, event_hash: str):
        return event_hash in self._event_dict
    
    def to_list(self, cutoff: Optional[float]=None) -> list[VerificationNodeData]:
        '''Iterates the timeline and builds the resultant list from the event data'''

        selected_nodes: list[VerificationNodeData] = []
        for event in self.bounded_iter(None, cutoff):
            event.update_verification_list(selected_nodes)
        return selected_nodes
    
    def get_latest_checksum(self, cutoff: Optional[float]=None):
        """Get's the latest checksum, usually to seed witness selection RNG from the entropy produced by the VNT at time 'cutoff'"""
        
        latest = self.latest_before(cutoff)
        
        if latest is None:
            raise ValueError('Calling on empty timeline is not allowed')
        
        return latest.checksum