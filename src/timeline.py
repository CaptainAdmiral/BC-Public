import asyncio
import bisect
from dataclasses import dataclass
from typing import Callable, Iterable, Protocol

import async_manager

@dataclass
class TimelineEvent:
    time: float
    callback: Callable


class TimelineException(Exception):
    ...


class TimeListener(Protocol):
    def on_time_change(
        self, old_time: float, new_time: float
    ) -> Iterable[TimelineEvent]:
        """Immediately schedules the returned timestamped callables before the time change takes place"""
        ...


_time: float = 0.0
_target_time = _time
_done_processing_event = asyncio.Event()
_done_processing_event.set()
subscribers: set[TimeListener] = set()
scheduled_events: list[TimelineEvent] = []

def get_scheduled_events():
    return scheduled_events


def cur_time():
    global _time
    return _time


def schedule_event(timestamp: float, callback: Callable):
    """Schedules an event to occur at the provided time"""
    global _time, scheduled_events

    bisect.insort(
        scheduled_events, TimelineEvent(timestamp, callback), key=lambda e: e.time
    )

    if timestamp < _time:
        raise TimelineException("Can't add an event before the current time")


def subscribe(listener: TimeListener):
    """Will call the subscribers on_time_change(self, time: float) method to get a list of scheduled events for that
    period every time the timeline is progressed"""

    global subscribers
    subscribers.add(listener)


def unsubscribe(listener: TimeListener):
    global subscribers
    subscribers.remove(listener)


async def process_events():
    global _time, _target_time, scheduled_events

    if not _done_processing_event.is_set():
        await _done_processing_event.wait()
        return

    _done_processing_event.clear()
    await async_manager.flush_event_loop()
    try:
        while scheduled_events and scheduled_events[0].time <= _target_time:
            scheduled_event = scheduled_events.pop(0)
            _time = max(_time, scheduled_event.time)
            scheduled_event.callback()
            await async_manager.flush_event_loop()
    finally:
        _done_processing_event.set()
        _time = _target_time


async def set_time(t: float):
    global _time

    await time_update(t)
    _time = t


async def time_update(t: float):
    """Simulates time elapsing until the specified time and triggers all scheduled events for that time period in order"""

    global _time, _target_time, scheduled_events, subscribers

    if t <= _target_time or t <= _time:
        return

    for ts in subscribers:
        events = ts.on_time_change(_target_time, t)
        for event in events:
            schedule_event(event.time, event.callback)

    _target_time = max(_target_time, t)
    await process_events()


async def pass_time(delta: float):
    """Simulates delta time elapsing and triggers all scheduled events for that time period in order"""
    global _time
    await time_update(_time + delta)


async def sleep(t: float):
    global _time

    event = asyncio.Event()
    schedule_event(_time + t, lambda: event.set())
    await event.wait()