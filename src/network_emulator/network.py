from typing import TYPE_CHECKING

import numpy as np

import timeline
from network_emulator import net_connection
from settings import BASE_TIMEOUT, NETWORK_DELAY, NETWORK_DELAY_VARIABILITY

if TYPE_CHECKING:
    from network_emulator.node import Node
    from protocol.protocols.std_protocol.std_protocol import StdProtocol
    from protocol.protocols.zero_protocol.zero_protocol import ZeroProtocol
    from protocol.protocols.abstract_protocol import AbstractProtocol

_nodes: dict[int, "Node[AbstractProtocol]"] = {}

# Special Nodes
_node_0: "Node[ZeroProtocol] | None" = None
_credit_origin: "Node[StdProtocol] | None" = None


def get_nodes():
    return _nodes


def get_node(address: int) -> "Node":
    return _nodes[address]


def get_credit_origin() -> "Node[StdProtocol]":
    assert(_credit_origin is not None)
    return _credit_origin


def set_credit_origin(node: "Node[StdProtocol]"):
    global _credit_origin
    _credit_origin = node


def get_node_0() -> "Node[ZeroProtocol]":
    assert(_node_0 is not None)
    return _node_0


def set_node_0(node: "Node[ZeroProtocol]"):
    global _node_0
    _node_0 = node


def get_delay():
    return np.random.normal(NETWORK_DELAY, NETWORK_DELAY * NETWORK_DELAY_VARIABILITY)


def join(node: "Node"):
    global _nodes
    _nodes[node.address] = node


async def connect(own_address: int, other_address: int) -> net_connection.NetConnection:
    own_node = get_node(own_address)
    other_node = get_node(other_address)

    if not own_node.active or not other_node.active:
        await timeline.sleep(BASE_TIMEOUT)
        raise TimeoutError("Timeout on network connection")

    nc = net_connection.NetConnection(own_node, other_node)
    other_node.accept_net_connection(nc.get_inverse())
    return nc
