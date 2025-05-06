import asyncio
from typing import Coroutine

tasks: set[asyncio.Task] = set()

def add_async_task(coro: Coroutine):
    task = asyncio.create_task(coro)
    tasks.add(task)
    task.add_done_callback(tasks.discard)

async def run():
    """This is the main entry point for running high level network commands such as sending currency between two nodes.
    Run in the main event loop directly after network initialization."""    
    
    while True:
        await asyncio.sleep(1)