import argparse
import asyncio
import logging
import uuid
from typing import cast

import timeline
from async_manager import wait_all_tasks
from network_emulator import network, out_of_network
from network_emulator.node import Node
from protocol.credit.credit_types import ContractType, Stake
from protocol.dialogue.dialogue_registry import validate_symetric_dialogues
from protocol.protocols.std_protocol.std_protocol import StdProtocol
from protocol.protocols.zero_protocol.zero_protocol import ZeroProtocol
from protocol.verification_net.vnt_event_factory import VNTEventFactory
from protocol.verification_net.vnt_types import (
    JoinData,
    JoinEvent,
    VerificationNetEventEnum,
    VNTEventPacket,
)
from run import run
from settings import (
    TIME_SCALE,
    TIME_TO_CONSISTENCY,
    TIMESTAMP_LENIENCY,
    TRANSACTION_WITNESSES,
    UPDATE_RATE,
    set_verbose,
)
from util import network_stats as net_stats

parser = argparse.ArgumentParser()
parser.add_argument(
    "--soft-crash",
    action="store_true",
    help="Wrap program in try/catch to ensure clean exit",
)
parser.add_argument("--verbose", action="store_true", help="toggle verbose output")
args = parser.parse_args()

set_verbose(args.verbose)

for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

file_handler = logging.FileHandler("logs.log", mode="w")
file_handler.setLevel(logging.DEBUG)


class Formatter(logging.Formatter):
    def format(self, record):
        record.timestamp = f"{timeline.cur_time():.2f}"
        return super().format(record)


console_formatter = Formatter("%(timestamp)s::%(levelname)s: %(message)s")
file_formatter = Formatter("%(asctime)s::%(timestamp)s::%(levelname)s: %(message)s")
console_handler.setFormatter(console_formatter)
file_handler.setFormatter(file_formatter)
root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)
root_logger.addHandler(console_handler)
root_logger.addHandler(file_handler)


async def initialize_network():
    """The initial network setup. The standard protocol should ship with these events baked in for security,
    but to keep the network initialization flexible this is not the case here."""

    node_0_node = Node[ZeroProtocol]()
    node_0 = ZeroProtocol(node_0_node)
    node_0_node.set_protocol(node_0)
    network.set_node_0(node_0_node)
    out_of_network.advertise(out_of_network.NODE_0_KEY, node_0.node_data)
    verification_net: list[Node[StdProtocol]] = []
    for _ in range(TRANSACTION_WITNESSES):
        node = Node[StdProtocol]()
        protocol = StdProtocol(node)
        node.set_protocol(protocol)
        verification_net.append(node)

    for node in verification_net:
        protocol = node.protocol

        stake = Stake(
            uuid=uuid.uuid4(),
            contract_type=ContractType.STAKE,
            address=protocol.address,
            public_key=protocol.public_key,
            amount=0,
            funds=(),
            timestamp=0.0,
        )

        signed_stake = node_0.sign(stake)
        join_data = JoinData(
            VerificationNetEventEnum.NODE_JOIN, signed_stake, stake.timestamp
        )
        event_packet = VNTEventPacket(join_data)
        event_packet = node_0.sign(event_packet)
        join_event = VNTEventFactory.event_from_packet(event_packet)
        node_0.verification_net_timeline.add(join_event)

        for n in verification_net:
            p: StdProtocol = cast(StdProtocol, n.protocol)
            je: JoinEvent = cast(
                JoinEvent, VNTEventFactory.event_from_packet(event_packet)
            )
            p.verification_net_timeline.add(je)
            p.stake = je.data.signed_stake.message

    credit_origin_node = Node[StdProtocol]()
    credit_origin = StdProtocol(credit_origin_node)
    credit_origin_node.set_protocol(credit_origin)

    network.set_credit_origin(credit_origin_node)
    out_of_network.advertise(out_of_network.CREDIT_ORIGIN_KEY, credit_origin.node_data)

    await timeline.set_time(TIME_TO_CONSISTENCY + TIMESTAMP_LENIENCY)
    await node_0.transfer_credit_to(10**20, credit_origin.node_data)


async def progress_time():
    try:
        while True:
            await timeline.pass_time(UPDATE_RATE * TIME_SCALE)
            await asyncio.sleep(UPDATE_RATE)
    except asyncio.CancelledError:
        return


async def async_main():
    time_manager = asyncio.create_task(progress_time())
    logging.info("Initializing network")
    await initialize_network()
    await wait_all_tasks()

    logging.info("\n" + net_stats.node_table().get_string())
    logging.info(f"Network Total: {net_stats.network_total()}")
    logging.info("Network Initialized")

    logging.info("Running network simulation")
    await run()
    logging.info("\n" + net_stats.node_table().get_string())
    logging.info(f"Network Total: {net_stats.network_total()}")
    await wait_all_tasks()
    logging.info("Network simulation finished")

    time_manager.cancel()


async def soft_exit_async_main():
    try:
        await async_main()
    except Exception as e:
        logging.exception(e, stack_info=True)


def main():
    validate_symetric_dialogues(StdProtocol)


if __name__ == "__main__":
    if args.soft_crash:
        try:
            main()
        except Exception as e:
            logging.exception(e, stack_info=True)

        asyncio.run(soft_exit_async_main())
    else:
        main()
        asyncio.run(async_main())
