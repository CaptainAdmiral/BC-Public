import asyncio
import logging
import traceback
from typing import Any, Callable, Coroutine

tasks: set[asyncio.Task] = set()


def add_async_task(coro: Coroutine):
    async def exception_wrapper(coro: Coroutine):
        try:
            await coro
        except Exception as e:
            tb = traceback.extract_tb(e.__traceback__)
            last_frame = tb[-1]
            logging.error(
                f"Exception raised in task: {e} {last_frame.filename} line {last_frame.lineno}"
            )
            for note in getattr(e, "__notes__", []):
                logging.error(note)
            logging.exception(e, stack_info=True)

    task = asyncio.create_task(exception_wrapper(coro))
    tasks.add(task)
    task.add_done_callback(tasks.discard)


async def wait_all_tasks():
    if not tasks:
        return
    await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)


async def flush_event_loop():
    async_depth = 10
    for _ in range(async_depth):
        await asyncio.sleep(0)


def as_async[**P](f: Callable[P, Any]):
    async def wrapper(*args: P.args, **kwargs: P.kwargs):
        return f(*args, **kwargs)

    return wrapper
