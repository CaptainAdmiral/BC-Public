import asyncio
import bisect
from dataclasses import dataclass
from typing import Callable, Iterable, Protocol

from async_manager import wait_all_tasks


@dataclass
class TimelineEvent:
    time: float
    callback: Callable


class TimeListener(Protocol):
    def on_time_change(self, old_time: float, new_time: float) -> Iterable[TimelineEvent]:
        """Immediately schedules the returned timestamped callables before the time change takes place"""
        ...


_time: float = 0.0
_target_time = _time
_processing_events = False
subscribers: set[TimeListener] = set()
scheduled_events: list[TimelineEvent] = []


def cur_time():
    global _time
    return _time


def schedule_event(time: float, callback: Callable):
    """Schedules an event to occur at the provided time"""
    global _time, _target_time, _processing_events, scheduled_events

    bisect.insort(scheduled_events, TimelineEvent(time, callback), key=lambda e: e.time)

    if time <= _target_time and not _processing_events:
        process_events_until(_target_time)


def subscribe(listener: TimeListener):
    """Will call the subscribers on_time_change(self, time: float) method to get a list of scheduled events for that
    period every time the timeline is progressed"""

    global subscribers
    subscribers.add(listener)


def unsubscribe(listener: TimeListener):
    global subscribers
    subscribers.remove(listener)


def process_events_until(time: float):
    global _time, _processing_events, scheduled_events

    assert _processing_events == False
    _processing_events = True

    while scheduled_events and scheduled_events[0].time <= time:
        scheduled_event = scheduled_events.pop(0)
        _time = scheduled_event.time
        scheduled_event.callback()
    _processing_events = False


async def set_time(time: float):
    global _time

    await time_update(time)
    await wait_all_tasks()
    _time = time


async def time_update(time: float):
    """Simulates time elapsing until the specified time and triggers all scheduled events for that time period in order"""

    global _time, _target_time, scheduled_events, subscribers

    _time = _target_time
    _target_time = time

    if time <= _time:
        return

    for ts in subscribers:
        events = ts.on_time_change(_time, _target_time)
        for event in events:
            schedule_event(event.time, event.callback)

    process_events_until(_target_time)


async def pass_time(delta: float):
    """Simulates delta time elapsing and triggers all scheduled events for that time period in order"""
    global _time, _target_time
    await time_update(_time + delta)
    _time = _target_time


async def sleep(time: float):
    global _time

    event = asyncio.Event()
    schedule_event(_time + time, lambda: event.set())
    await event.wait()
