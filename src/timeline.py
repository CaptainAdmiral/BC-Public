import bisect
from dataclasses import dataclass
from typing import Callable, Iterable, Protocol


@dataclass
class TimelineEvent:
    time: float
    callback: Callable


class TimeListener(Protocol):
    def on_time_change(self, time: float) -> Iterable[TimelineEvent]:
        """Immediately schedules the returned timestamped callables before the time change takes place"""
        ...


_time: float = 0.0
subscribers: set[TimeListener] = set()
scheduled_events: list[TimelineEvent] = []


def cur_time():
    return _time


def schedule_event(time: float, callback: Callable):
    """Schedules an event to occur at the provided time"""
    bisect.insort(scheduled_events, TimelineEvent(time, callback), key=lambda e: e.time)


def subscribe(listener: TimeListener):
    """Will call the subscribers on_time_change(self, time: float) method to get a list of scheduled events for that
    period every time the timeline is progressed"""

    global subscribers
    subscribers.add(listener)


def unsubscribe(listener: TimeListener):
    global subscribers
    subscribers.remove(listener)


def set_time(time: float):
    """Simulates time elapsing until the specified time and triggers all scheduled events for that time period in order"""

    global _time, scheduled_events, subscribers

    if time < _time:
        raise ValueError("time cannot be less than the current time!")

    for ts in subscribers:
        events = ts.on_time_change(_time)
        for event in events:
            schedule_event(event.time, event.callback)

    while scheduled_events and scheduled_events[0].time <= _time:
        scheduled_events.pop(0).callback()


def pass_time(delta: float):
    """Simulates delta time elapsing and triggers all scheduled events for that time period in order"""
    global _time
    set_time(_time + delta)
