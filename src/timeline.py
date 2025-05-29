from typing import Callable, Iterable, Protocol, cast

from sortedcontainers import SortedList

type TimelineEvent = tuple[float, Callable]

class TimeListener(Protocol):
    def on_time_change(self, time: float) -> Iterable[TimelineEvent]:
        '''Immediately schedules the returned timestamped callables before the time change takes place'''
        ...

_time: float = 0.0
subscribers: set[TimeListener]  = set()
scheduled_events: SortedList = SortedList(key=lambda te: te[0])

def cur_time():
    return _time

def schedule_event(time: float, callback: Callable):
    '''Schedules an event to occur at the provided time'''
    scheduled_events.add((time, callback))

def subscribe(listener: TimeListener):
    '''Will call the subscribers on_time_change(self, time: float) method to get a list of scheduled events for that
    period every time the timeline is progressed'''

    global subscribers
    subscribers.add(listener)
    
def unsubscribe(listener: TimeListener):
    global subscribers
    subscribers.remove(listener)

def set_time(time: float):
    '''Simulates time elapsing until the specified time and triggers all scheduled events for that time period in order'''
    
    global _time, scheduled_events, subscribers

    if time < _time:
        raise ValueError('time cannot be less than the current time!')

    for ts in subscribers:
        events = ts.on_time_change(_time)
        for event in events:
            schedule_event(*event)
    
    events_to_process = list(scheduled_events.irange(_time, time)) # TODO update as iterating
    i = 0
    while i < len(events_to_process):
        event = cast(TimelineEvent, events_to_process[i])
        if event[0] > _time:
            break
        event[1]()
        i += 1
    
    scheduled_events = SortedList(scheduled_events.irange(minimum=time, maximum=None, inclusive=(False, True))) 
    _time = time

def pass_time(delta: float):
    '''Simulates delta time elapsing and triggers all scheduled events for that time period in order'''
    global _time
    set_time(_time + delta)
