import math
from typing import Any, Callable, Iterable, Iterator, Optional
from util.timestamped import Timestamped

class _ChronologyNode(Timestamped):
    def __init__(self, timestamp: float):
        self._timestamp = timestamp
        self._prev: _ChronologyNode | None = None
        self._next: _ChronologyNode | None = None
        
    @property
    def timestamp(self) -> float:
        return self._timestamp

    @property
    def prev(self):
        return self._prev

    @property
    def next(self):
        return self._next

class _Event[T](_ChronologyNode):
    
    def __init__(self, event: T, key: Callable[[T], float] | None = None):
        if key is not None:
            timestamp = key(event)
        elif isinstance(event, Timestamped):
            timestamp = event.timestamp
        else:
            raise TypeError('Expected timestamp attribute on event! If this was intentional and no such attribute exists please provide a mapping to a timestamp using the key param')
        
        super().__init__(timestamp)
        self.data: T = event

class _EpochMarker(_ChronologyNode):
    
    def __init__(self, timestamp: float):
        super().__init__(timestamp)

class Chronology[T]:
    '''Linked list which preserves a sort on it's elements by timestamp'''
    
    def __init__(self,
                 iterable: Optional[Iterable[T]] = None,
                 *,
                 epoch_length: Optional[float] = None,
                 key: Optional[Callable[[T], float]] = None,
                 secondary_sort: Optional[Callable[[T], Any]] = None):
        '''
        Args:
            iterable: Optional[Iterable[T]]
                iterable of timestamped events to initialize chronology
            epoch_length: Optional[float]
                setting this argument will cause additional nodes to be injected into the chronology at regular time intervals for efficiency when indexing.
            key: Optional[Callable[[T], float]]
                optionally provide a mapping from your data type to a timestamp if it doesn't use the Timestamped protocol
            secondary_sort: Optional[Callable[T], Any]
                optionally provide a secondary sort for values that have the same timestamp. Defaults to insertion order'''

        self._latest: _ChronologyNode | None = None
        self._earliest: _ChronologyNode | None = None
        self._key = key
        self._epoch_length = epoch_length
        self.epochs: list[_EpochMarker] = []
        self._len: int = 0
        self._secondary_sort = secondary_sort

        if iterable is not None:
            for el in iterable:
                self.add(el)

    def __len__(self):
        return self._len
    
    def __setitem__(self, key, value):
        raise TypeError(f"{self.__class__.__name__} object does not support item assignment")
    
    def __delitem__(self, index):
        raise TypeError('f"{self.__class__.__name__} object does not support deletion')
    
    def __getitem__(self, key: slice) -> Iterator[T]: # type: ignore
        if isinstance(key, int):
            raise TypeError("Must use slice indexing to specify a time range")
        if not isinstance(key, slice):
            raise TypeError("Invalid argument type")
        
        if key.step is not None:
            raise TypeError("Does not accept step")
        
        return self.bounded_iter(key.start, key.stop)

    def bounded_iter(self, start: float | None, stop: float | None) -> Iterator[T]:
        '''Returns an iterator for the given time range in the closed interval [start, stop]'''

        if not self._earliest or not self._latest:
            return
        
        event = None
        if start is None:
            start = self._earliest.timestamp
            event = self._earliest
        if stop is None:
            stop = self._latest.timestamp
        
        if start > stop:
            raise ValueError('use bounded_riter for iterating backwards in time')
        
        if event is None:
            event = self._latest_before(start)

        while event is not None and event.timestamp <= stop:
            if isinstance(event, _Event):
                yield event.data
            event = event._next

    def bounded_riter(self, start: float | None, stop: float | None) -> Iterator[T]:
        '''Returns an iterator for the given time range in the closed interval [start, stop]'''

        if not self._earliest or not self._latest:
            return

        event = None  
        if start is None:
            start = self._latest.timestamp
            event = self._latest
        if stop is None:
            stop = self._earliest.timestamp
        
        if start < stop:
            raise ValueError('use bounded_iter for iterating forwards in time')
        
        if event is None:
            event = self._earliest_after(start)
        
        while event is not None and event.timestamp >= stop:
            if isinstance(event, _Event):
                yield event.data
            event = event._prev
    
    def _f_wrapped_iter(self):
        event = self._earliest
        while event is not None:
            yield event
            event = event._next

    def _r_wrapped_iter(self):
        event = self._latest
        while event is not None:
            yield event
            event = event._prev

    def wrapped_iter_from(self, node: _ChronologyNode, reverse=False) -> Iterator[_Event[T]]:
        event = node
        while event is not None:
            if isinstance(event, _Event):
                yield event
            event = event.prev if reverse else event.next

    def iter_from(self, node: _ChronologyNode, reverse=False) -> Iterator[T]:
        '''Iterates starting at the given node'''
        return (event.data for event in self.wrapped_iter_from(node, reverse=reverse))

    def __iter__(self) -> Iterator[T]:
        return (el.data for el in self._f_wrapped_iter() if isinstance(el, _Event))

    def __reversed__(self) -> Iterator[T]:
        return (el.data for el in self._r_wrapped_iter() if isinstance(el, _Event))
    
    def _get_nearest_epoch(self, time: float) -> _EpochMarker | None:
        if not self.epochs or not self._epoch_length:
            return None
        
        earliest = self.epochs[0]
        if earliest.timestamp <= time:
            return earliest
        
        index = round((time - earliest.timestamp) / self._epoch_length)
        if index >= len(self.epochs):
            index = len(self.epochs) - 1

        return self.epochs[index]
    
    def _get_nearest_O1(self, time: float) -> _ChronologyNode | None:
        '''Get's the nearest node that can be accessed in constant time '''
        if self._latest is None or self._earliest is None:
            return None
        if time < self._earliest.timestamp:
            return self._earliest
        elif time > self._latest.timestamp:
            return self._latest
        
        nearest_epoch = self._get_nearest_epoch(time)
        args = [self._earliest, self._latest]
        if nearest_epoch is not None:
            args.append(nearest_epoch)
        return min(*args, key=lambda node: abs(time - node.timestamp))
    
    def _latest_before(self, time: float) -> _ChronologyNode | None:
        '''
        Args:
            time: float
                cutoff

        Returns:
            _ChronologyNode: The latest node occurring before the cutoff (inclusive)
            
        If there are multiple nodes with a timestamp of time, this function will return the leftmost node with that timestamp'''
        
        nearest_node = self._get_nearest_O1(time)

        if nearest_node is None:
            return None
        
        node = nearest_node
        if nearest_node.timestamp < time:
            while node._next is not None and node.timestamp < time and node._next.timestamp <= time:
                node = node._next
        else:
            while node._prev is not None and node._prev.timestamp >= time:
                node = node._prev
                
        return node
    
    def _earliest_after(self, time: float) -> _ChronologyNode | None:
        '''
        Args:
            time: float
                cutoff

        Returns:
            _ChronologyNode: The earliest node occurring after the cutoff (inclusive)

        If there are multiple nodes with a timestamp of time, this function will return the rightmost node with that timestamp'''
        
        
        nearest_node = self._get_nearest_O1(time)

        if nearest_node is None:
            return None
        
        node = nearest_node
        if nearest_node.timestamp > time:
            while node._prev is not None and node.timestamp > time and node._prev.timestamp >= time:
                node = node._prev
        else:
            while node._next is not None and node._next.timestamp <= time:
                node = node._next
                
        return node
    
    
    def add(self, event: T) -> _Event[T]:
        '''Adds an event to the timeline.
        
        Returns:
            _Event: The new node containing the event data just added
        '''

        # Code is very WET here but refactoring it's not worth the extra verbosity

        wrapped_event = _Event(event, key=self._key)
        if self._latest is None or self._earliest is None:
            self._latest = wrapped_event
            self._earliest = wrapped_event

            if self._epoch_length:
                epoch = _EpochMarker(self._epoch_length * (wrapped_event.timestamp // self._epoch_length))
                self.epochs.append(epoch)
                wrapped_event._prev = epoch
                epoch._next = wrapped_event
                self._earliest = epoch
        else:
            if wrapped_event.timestamp < self._earliest.timestamp:

                # Add epochs in between earliest epoch and event
                if self._epoch_length:
                    assert(self.epochs)
                    earliest_epoch = self.epochs[0]
                    new_epochs = []
                    ts = earliest_epoch.timestamp 
                    epoch_idx = round(ts / self._epoch_length)
                    while True:
                        epoch_idx -= 1
                        ts = self._epoch_length * epoch_idx
                        if ts < wrapped_event.timestamp:
                            break
                        epoch = _EpochMarker(ts)
                        new_epochs.append(epoch)

                    # Link epochs and update pointer to earliest
                    if new_epochs:
                        prev_node = self._earliest
                        for epoch in new_epochs:
                            prev_node._prev = epoch
                            epoch._next = prev_node
                            prev_node = epoch
                    
                        self.epochs = list(reversed(new_epochs)) + self.epochs
                        self._earliest = self.epochs[0]
                
                self._earliest._prev = wrapped_event
                wrapped_event._next = self._earliest

            elif wrapped_event.timestamp > self._latest.timestamp:

                # Add epochs in between latest epoch and event
                if self._epoch_length:
                    assert(self.epochs)
                    latest_epoch = self.epochs[-1]
                    new_epochs = []
                    ts = latest_epoch.timestamp
                    epoch_idx = round(ts / self._epoch_length)
                    while True:
                        epoch_idx += 1
                        ts = self._epoch_length * epoch_idx
                        if ts > wrapped_event.timestamp:
                            break
                        epoch = _EpochMarker(ts)
                        new_epochs.append(epoch)

                    # Link epochs and update pointer to latest
                    if new_epochs:
                        prev_node = self._latest
                        for epoch in new_epochs:
                            prev_node._next = epoch
                            epoch._prev = prev_node
                            prev_node = epoch
                    
                        self.epochs += new_epochs
                        self._latest = self.epochs[-1]

                self._latest._next = wrapped_event
                wrapped_event._prev = self._latest
                        
            else:
                node = self._latest_before(wrapped_event.timestamp)
                assert(node is not None)

                if self._secondary_sort is not None:
                    while node._next and node.timestamp == node._next.timestamp:
                        if isinstance(node, _Event) and isinstance(node._next, _Event):
                            if self._secondary_sort(node._next.data) < self._secondary_sort(wrapped_event.data):
                                break
                        node = node._next

                if node._next is not None:
                    node._next._prev = wrapped_event
                wrapped_event._next = node._next
                node._next = wrapped_event
                wrapped_event._prev = node
        
        while self._earliest.prev is not None:
            self._earliest = self._earliest.prev

        while self._latest.next is not None:
            self._latest = self._latest.next

        self._len += 1
        return wrapped_event
        
    def earliest(self):
        return next(iter(self), None)
    
    def latest(self):
        return next(reversed(self), None)
    
    def latest_before(self, time: float | None):
        return next(self.bounded_riter(time, None), None)
    
    def earliest_after(self, time: float | None):
        return next(self.bounded_iter(time, None), None)