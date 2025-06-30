"""Models behaviors that occur outside of the network (such as exchange of information over the wider internet)"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from protocol.protocols.common_types import NodeData

NODE_0_KEY = "node_0"
CREDIT_ORIGIN_KEY = "credit_origin"


_advertised_nodes: dict[str, "NodeData"] = {}
"""Nodes that are advertising themselves somehow"""


def advertise(key: str, node_data: "NodeData"):
    _advertised_nodes[key] = node_data


def stop_advertising(key: str):
    del _advertised_nodes[key]


def get_advertised_node(key) -> "NodeData":
    return _advertised_nodes[key]