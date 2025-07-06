import asyncio
import logging
from datetime import timedelta

from network_emulator import network
from network_emulator.node import Node
from protocol.protocols.std_protocol.std_protocol import StdProtocol
from settings import ROLLOVER_PERIOD, STAKE_AMOUNT
from timeline import pass_time
from util import network_stats as net_stats


async def run():
    """Put whatever procedural network actions you like here, this function will
    be run directly after initializing the network"""

    node_0 = network.get_node_0()
    credit_origin = network.get_credit_origin()

    tasks: set[asyncio.Task] = set()

    await pass_time(timedelta(hours=1).total_seconds())
    await pass_time(timedelta(hours=1).total_seconds())

    nodes: list[Node[StdProtocol]] = []

    for _ in range(5):
        node = Node()
        protocol = StdProtocol(node)
        node.set_protocol(protocol)
        nodes.append(node)

    for node in nodes:
        tasks.add(
            asyncio.create_task(
                credit_origin.protocol.transfer_credit_to(
                    STAKE_AMOUNT + 1_000_000, node.protocol.node_data
                )
            )
        )

    await asyncio.wait(tasks)
    tasks.clear()
    await pass_time(timedelta(hours=1).total_seconds())

    logging.info("\n" + net_stats.node_table().get_string())
    logging.info(f"Network Total: {net_stats.network_total()}")

    for node in nodes:
        tasks.add(asyncio.create_task(node.protocol.join_verification_net()))

    logging.info("\n" + net_stats.node_table().get_string())
    logging.info(f"Network Total: {net_stats.network_total()}")

    await asyncio.wait(tasks)
    tasks.clear()
    await pass_time(timedelta(hours=1).total_seconds() + ROLLOVER_PERIOD * 2)

    node_1 = Node[StdProtocol]()
    node_1_protocol = StdProtocol(node_1)
    node_1.set_protocol(node_1_protocol)
    
    await credit_origin.protocol.transfer_credit_to(100_000_000, node_1_protocol.node_data)

    node_2 = Node[StdProtocol]()
    node_2_protocol = StdProtocol(node_2)
    node_2.set_protocol(node_2_protocol)
    
    await node_1_protocol.transfer_credit_to(100_000, node_2_protocol.node_data)

    await pass_time(ROLLOVER_PERIOD * 2)

    logging.info("\n" + net_stats.node_table().get_string())
    logging.info(f"Network Total: {net_stats.network_total()}")