import asyncio
import logging
from datetime import timedelta

from async_manager import wait_all_tasks
from network_emulator import network
from network_emulator.node import Node
from protocol.protocols.std_protocol.std_protocol import StdProtocol
from settings import STAKE_AMOUNT
from timeline import pass_time
from util import network_stats as net_stats


async def run():
    """Put whatever procedural network actions you like here, this function will
    be run directly after initializing the network"""

    node_0 = network.get_node_0()
    credit_origin = network.get_credit_origin()

    tasks: set[asyncio.Task] = set()

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
    await wait_all_tasks()

    logging.info("\n" + net_stats.node_table().get_string())
    logging.info(f"Network Total: {net_stats.network_total()}")

    for node in nodes:
        tasks.add(asyncio.create_task(node.protocol.join_verification_net()))

    await asyncio.wait(tasks)
    tasks.clear()
    await pass_time(timedelta(hours=1).total_seconds())
