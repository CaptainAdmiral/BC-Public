import asyncio
from typing import TYPE_CHECKING

import numpy as np

from network_emulator import net_connection
from settings import BASE_TIMEOUT, NETWORK_DELAY, NETWORK_DELAY_VARIABILITY, TIME_SCALE

if TYPE_CHECKING:
    from network_emulator.node import Node

nodes: dict[int, "Node"] = {}


def _get_node(address: int) -> "Node":
    return nodes[address]


async def delay():
    await asyncio.sleep(
        np.random.normal(NETWORK_DELAY, NETWORK_DELAY * NETWORK_DELAY_VARIABILITY)
        * TIME_SCALE
    )


def join(node: "Node"):
    global nodes
    nodes[node.address] = node


async def connect(own_address: int, other_address: int) -> net_connection.NetConnection:
    own_node = _get_node(own_address)
    other_node = _get_node(other_address)

    if not own_node.active or not other_node.active:
        await asyncio.sleep(BASE_TIMEOUT * TIME_SCALE)
        raise TimeoutError("Timeout on network connection")

    await delay()
    nc = net_connection.NetConnection(own_node, other_node)

    other_node.accept_net_connection(nc.get_inverse())
    return nc
