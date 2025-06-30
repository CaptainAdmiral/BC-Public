from dataclasses import dataclass
from enum import StrEnum, auto
from typing import TYPE_CHECKING, Any, Callable, Optional

from prettytable import PrettyTable

from network_emulator import network
from protocol.protocols.std_protocol.std_protocol import StdProtocol

if TYPE_CHECKING:
    from network_emulator.node import Node
    from protocol.protocols.abstract_protocol import AbstractProtocol

class NodeTableColumns(StrEnum):
    ADDRESS = auto()
    PUBLIC_KEY = auto()
    BALANCE = auto()
    TOTAL_CREDIT = auto()
    VERIFICATION_NODE = auto()


@dataclass
class TableColumn:
    id: NodeTableColumns
    pretty_name: str
    data: Callable[["Node[AbstractProtocol]"], str]
    default: bool


TABLE_COLUMNS = [
    TableColumn(
        NodeTableColumns.ADDRESS,
        "Address",
        lambda node: (
            node.protocol.stat_address() if node.protocol is not None else "n/a"
        ),
        True,
    ),
    TableColumn(
        NodeTableColumns.PUBLIC_KEY,
        "Public Key",
        lambda node: (
            node.protocol.stat_public_key() if node.protocol is not None else "n/a"
        ),
        False,
    ),
    TableColumn(
        NodeTableColumns.BALANCE,
        "Available Balance",
        lambda node: (
            node.protocol.stat_balance() if node.protocol is not None else "n/a"
        ),
        True,
    ),
    TableColumn(
        NodeTableColumns.TOTAL_CREDIT,
        "Held Credit",
        lambda node: (
            node.protocol.stat_total_credit() if node.protocol is not None else "n/a"
        ),
        True,
    ),
    TableColumn(
        NodeTableColumns.VERIFICATION_NODE,
        "Verifier",
        lambda node: (
            node.protocol.stat_verifier() if node.protocol is not None else "n/a"
        ),
        True,
    ),
]


def node_table(
    columns: Optional[list[NodeTableColumns]] = None,
    *,
    filter: Optional[Callable[["Node"], bool]] = None,
    sort: Optional[Callable[["Node"], Any]] = None
):
    if columns is None:
        table_columns = [column for column in TABLE_COLUMNS if column.default]
    else:
        table_columns = [column for column in TABLE_COLUMNS if column.id in columns]

    table = PrettyTable()
    table.field_names = [column.pretty_name for column in table_columns]

    nodes = list(network.get_nodes().values())
    if sort is not None:
        nodes.sort(key=sort)  # type: ignore

    for node in nodes:
        if filter is None or filter(node):
            table.add_row([column.data(node) for column in table_columns])

    return table


def network_total():
    """The total currency in circulation among nodes running a standard protocol"""

    total = 0
    for node in network.get_nodes().values():
        protocol = node.protocol
        if not isinstance(protocol, StdProtocol):
            continue
        total += protocol.wallet.total_credit()
    return total
