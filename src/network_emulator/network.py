import asyncio
import numpy as np
from network_emulator import Node, NetConnection
from settings import NETWORK_DELAY, NETWORK_DELAY_VARIABILITY

class NetworkException(Exception):
    ...

nodes: dict[int, Node] = {}

async def delay():
    await asyncio.sleep(np.random.normal(NETWORK_DELAY, NETWORK_DELAY*NETWORK_DELAY_VARIABILITY))

async def connect_to_node(self_node: Node, other_node: Node) -> NetConnection:
    nc = NetConnection(self_node, other_node)
    await delay()
    other_node.accept_net_connection(nc.get_inverse())
    return nc

def get_node(address: int) -> Node:
    return nodes[address]