from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Optional, cast

from sortedcontainers import SortedList
from cryptography.signature import Signed
from protocol.std_protocol.std_protocol import VerificationNodeData
from protocol.verification_net.vnt_event_factory import VNTEventFactory
from protocol.verification_net.vnt_types import VNTEventPacket, VNTUpdateHelper, VerificationNetEvent
from timeline import cur_time
from util.chronology import _ChronologyNode, _Event, Chronology

@dataclass
class EventWithTimeAdded:
    event: _Event[VerificationNetEvent]
    time_added: float

class VerificationNetTimeline:
    '''Collection to automatically sort and rehash validation events by timestamp'''

    def __init__(self, iterable: Optional[Iterable[VerificationNetEvent]] = None, *, epoch_length: Optional[float] = None):
        def secondary_sort(event: VerificationNetEvent):
            return event.id
        
        self._timeline: Chronology[VerificationNetEvent] = Chronology(iterable, epoch_length=epoch_length, secondary_sort=secondary_sort)
        self._checksum_dict: dict[str, _Event[VerificationNetEvent]] = {} # dict[event_checksum, event]
        self._event_dict: dict[str, _Event[VerificationNetEvent]] = {} # dict[event_hash, event]
        self._events_as_added: SortedList = SortedList(key=lambda ewta: cast(EventWithTimeAdded, ewta).time_added)
        self._listeners: set[Callable[[VerificationNetEvent], None]] # Callable[event_type, event_data]

    def __iter__(self):
        return iter(self._timeline)

    def __reversed__(self):
        return reversed(self._timeline)

    def __len__(self):
        return len(self._timeline)
    
    def __setitem__(self, key, value):
        raise TypeError(f"{self.__class__.__name__} object does not support item assignment")
    
    def __getitem__(self, key: slice) -> Iterator[VerificationNetEvent]:
        return self._timeline[key]
    
    def __contains__(self, event: VerificationNetEvent):
        return event.id in self._event_dict 

    def _update_checksums_from(self, node: _Event[VerificationNetEvent]):
        '''Update each of the subsequent event's hashes using its own data and the previous event's hash'''

        last_hash = node.data.prev_hash
        for event in self._timeline.wrapped_iter_from(node):
            del self._checksum_dict[event.data.checksum]
            event.data.prev_hash = last_hash
            event.data.update_checksum()
            self._checksum_dict[event.data.checksum] = event
            last_hash = event.data.checksum
    
    def _add_without_update(self, event: VerificationNetEvent):
        event_id = event.id
        if event_id in self._event_dict:
            return self._event_dict[event_id]

        node = self._timeline.add(event)
        self._checksum_dict[event.checksum] = node
        self._event_dict[event_id] = node
        self._events_as_added.add(EventWithTimeAdded(event=node, time_added=cur_time()))
        return node
    
    def add(self, event: VerificationNetEvent):
        node = self._add_without_update(event)
        self._update_checksums_from(node)
        return node

    def add_from_packets(self, packets: Iterable[Signed[VNTEventPacket]]):
        earliest_node: _Event[VerificationNetEvent] | None = None
        for packet in packets:
            event = VNTEventFactory.event_from_packet(packet)
            node = self._add_without_update(event)
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
    
    def event_from_id(self, event_id: str):
        if event_id not in self._event_dict:
            raise KeyError(f"No such event id in timeline: {event_id}")
        return self._event_dict[event_id].data
    
    def to_list(self, cutoff: Optional[float]=None, excluded_event_ids: Optional[set[str]]=None) -> list[VerificationNodeData]:
        '''Iterates the timeline and builds the resultant list from the event data'''

        selected_nodes: VNTUpdateHelper = VNTUpdateHelper()
        for event in self._timeline.bounded_iter(None, cutoff):
            if excluded_event_ids and event.id in excluded_event_ids:
                continue
            event.update_verification_list(selected_nodes)
        return selected_nodes.to_list()
    
    def get_latest_checksum(self, cutoff: Optional[float]=None):
        """Get's the latest checksum, usually to seed witness selection RNG from the entropy produced by the VNT at time 'cutoff'"""
        
        latest = self._timeline.latest_before(cutoff)
        
        if latest is None:
            raise ValueError('Calling on empty timeline is not allowed')
        
        return latest.checksum
    
    def events_by_time_added(self, start: Optional[float], stop: Optional[float]) -> list[EventWithTimeAdded]:
        """Returns events added within the time interval [start, stop]"""
        return list(self._events_as_added.irange(minimum=start, maximum=stop))
    
    def subscribe(self, event_handler: Callable[[VerificationNetEvent], None]):
        '''Will trigger the callback every time a new event is added'''
        self._listeners.add(event_handler)
    
    def unsubscribe(self, event_handler: Callable[[VerificationNetEvent], None]):
        self._listeners.remove(event_handler)

    def bounded_iter(self, start: float | None, stop: float | None):
        '''Returns an iterator for the given time range in the closed interval [start, stop]'''
        return self._timeline.bounded_iter(start, stop)

    def bounded_riter(self, start: float | None, stop: float | None):
        '''Returns an iterator for the given time range in the closed interval [start, stop]'''
        return self._timeline.bounded_riter(start, stop)

    def wrapped_iter_from(self, node: _ChronologyNode, reverse=False):
        return self._timeline.wrapped_iter_from(node, reverse=reverse)

    def iter_from(self, node: _ChronologyNode, reverse=False):
        '''Iterates starting at the given node'''
        return self._timeline.iter_from(node, reverse=reverse)
    
    def earliest(self):
        return self._timeline.earliest()
    
    def latest(self):
        return self._timeline.latest()
    
    def latest_before(self, time: float | None):
        return self._timeline.latest_before(time)
    
    def earliest_after(self, time: float | None):
        return self._timeline.earliest_after(time)