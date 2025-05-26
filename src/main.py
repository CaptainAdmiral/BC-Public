import argparse
import asyncio
import logging
import uuid
from typing import cast

from network_emulator.node import Node, ProtocolSelectionBehaviour
from protocol import protocol_factory
from protocol.credit.credit_types import ContractType, Stake
from protocol.dialogue.dialogue_registry import validate_symetric_dialogues
from protocol.protocols.std_protocol.std_protocol import StdProtocol
from protocol.protocols.zero_protocol.zero_protocol import ZeroProtocol
from protocol.verification_net.vnt_event_factory import VNTEventFactory
from protocol.verification_net.vnt_types import (
    JoinData,
    JoinEvent,
    VerificationNetEventEnum,
)
from run import run
from settings import TRANSACTION_WITNESSES, set_verbose

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

console_formatter = logging.Formatter("%(levelname)s : %(message)s")
file_formatter = logging.Formatter("%(asctime)s : %(levelname)s : %(message)s")
console_handler.setFormatter(console_formatter)
file_handler.setFormatter(file_formatter)
root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)
root_logger.addHandler(console_handler)
root_logger.addHandler(file_handler)


def register_protocols():
    protocol_factory.register_protocol(StdProtocol)


async def initialize_network():
    """The initial network setup. The standard protocol should ship with these events baked in for security,
    but to keep the network initialization flexible this is not the case here."""

    node_0_node = Node(protocol_selection=ProtocolSelectionBehaviour.USE_ZERO)
    node_0: ZeroProtocol = cast(ZeroProtocol, node_0_node.protocol)
    verification_net: list[Node] = [
        Node(protocol_selection=ProtocolSelectionBehaviour.USE_STD)
        for i in range(TRANSACTION_WITNESSES)
    ]

    for node in verification_net:
        protocol: StdProtocol = cast(StdProtocol, node.protocol)

        stake = Stake(
            uuid=uuid.uuid4(),
            contract_type=ContractType.STAKE,
            address=protocol.address,
            public_key=protocol.public_key,
            amount=0,
            funds=(),
            timestamp=0,
        )

        signed_stake = node_0.sign(stake)
        join_data = JoinData(signed_stake, stake.timestamp)
        event_packet = VNTEventFactory.packet_from_data(
            VerificationNetEventEnum.NODE_JOIN, join_data
        )
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

    credit_origin_node = Node(protocol_selection=ProtocolSelectionBehaviour.USE_STD)
    credit_origin = cast(StdProtocol, credit_origin_node.protocol)

    await node_0.transfer_credit_to(10**20, credit_origin.node_data)


async def async_main():
    await initialize_network()
    await run()


async def soft_exit_async_main():
    try:
        await async_main()
    except Exception as e:
        logging.exception(e, stack_info=True)


def main():
    register_protocols()
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
