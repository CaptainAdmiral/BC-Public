import asyncio
import uuid
from typing import TYPE_CHECKING, Optional

from crypto.signature import Signed
from protocol.credit.credit_types import ContractType, Receipt, Transaction
from protocol.dialogue.const import ControlPacket, DialogueEnum
from protocol.dialogue.dialogue_registry import DialogueType, dialogue_registrars
from protocol.dialogue.dialogue_types import DialogueException
from protocol.dialogue.packets import LatestChecksumPacket, Nullable
from protocol.dialogue.util.contact_util import filter_exceptions
from protocol.dialogue.util.dialogue_util import DialogueUtil
from protocol.dialogue.util.rng_seed import RNGSeed
from protocol.dialogue.util.witness_selection_util import SelectedNode, select_witnesses
from protocol.protocols.common_types import NodeData
from protocol.verification_net.vnt_event_factory import VNTEventFactory
from protocol.verification_net.vnt_types import VNTEventPacket
from timeline import cur_time

if TYPE_CHECKING:
    from protocol.protocols.zero_protocol.zero_protocol import ZeroProtocol


DIALOGUES: dict[str, DialogueType] = {}
RESPONSES: dict[str, DialogueType] = {}
register_init, register_response = dialogue_registrars(DIALOGUES, RESPONSES)


@register_init(DialogueEnum.HANDSHAKE)
async def handshake(du: DialogueUtil, protocol: "ZeroProtocol"):
    await du.expect_acknowledgement()


@register_response(DialogueEnum.HANDSHAKE)
async def handshake_response(du: DialogueUtil, protocol: "ZeroProtocol"):
    du.acknowledge()


@register_init(DialogueEnum.CHECK_SAME_VNT)
async def check_same_vnt(
    du: DialogueUtil, protocol: "ZeroProtocol", cutoff: Optional[float] = None
) -> bool:
    """See if the checksums on the verification timeline match until the given cutoff"""

    await du.expect_acknowledgement()

    latest_before = protocol.verification_net_timeline.latest_before(cutoff)
    if latest_before is None:
        raise DialogueException("Empty VNT timeline")

    du.reply(Nullable(cutoff))

    success = await du.expect(ControlPacket)
    if success == ControlPacket.SUCCESS:
        du.acknowledge()
    else:
        return False

    checksum = await du.expect(str)
    return checksum == latest_before.checksum


@register_response(DialogueEnum.CHECK_SAME_VNT)
async def check_same_vnt_response(du: DialogueUtil, protocol: "ZeroProtocol"):
    du.acknowledge()
    cutoff_packet = await du.expect(Nullable[float])
    cutoff = cutoff_packet.val

    latest_before = protocol.verification_net_timeline.latest_before(cutoff)
    if latest_before is None:
        du.reply(ControlPacket.FAILURE)
        return
    du.reply(ControlPacket.SUCCESS)
    await du.expect_acknowledgement()

    checksum = latest_before.checksum
    du.reply(checksum)
    return


@register_init(DialogueEnum.GET_LATEST_HASH)
async def find_latest_checksum(
    du: DialogueUtil, protocol: "ZeroProtocol"
) -> str | None:
    """Finds the latest checksum shared between this node and another node,
    which is exactly the point the two verification timelines start to differ"""

    await du.expect_acknowledgement()
    same_vnt = await check_same_vnt(du, protocol)
    if same_vnt:
        latest = protocol.verification_net_timeline.latest()
        assert latest is not None
        return latest.checksum

    du.reply(ControlPacket.FAILURE)
    await du.expect_acknowledgement()

    checksums = []
    try:
        skip = 0
        itr = reversed(protocol.verification_net_timeline)
        checksums.append(next(itr).checksum)
        while True:
            for _ in range(2**skip):
                for _ in reversed(protocol.verification_net_timeline):
                    next(itr)
            skip += 1

    except StopIteration as e:
        earliest = protocol.verification_net_timeline.earliest()
        if earliest:
            checksums.append(earliest.checksum)

    du.reply(checksums)
    res = await du.expect(ControlPacket)
    if res == ControlPacket.FAILURE:
        return None

    if res == ControlPacket.SUCCESS:
        du.acknowledge()
        latest = await du.expect(str)
        return latest


@register_response(DialogueEnum.GET_LATEST_HASH)
async def find_latest_checksum_response(
    du: DialogueUtil, protocol: "ZeroProtocol"
) -> str | None:
    du.acknowledge()
    await check_same_vnt_response(du, protocol)
    await du.expect(ControlPacket.FAILURE)
    du.acknowledge()
    checksums = await du.expect(list[str])

    for cs in checksums:
        if protocol.verification_net_timeline.includes_checksum(cs):
            matching_cs = cs
            du.reply(ControlPacket.SUCCESS)
            await du.expect_acknowledgement()
            du.reply(matching_cs)
            return matching_cs

    du.reply(ControlPacket.FAILURE)
    return None


@register_init(DialogueEnum.REQUEST_MISSING_EVENTS)
async def request_missing_events(
    du: DialogueUtil, protocol: "ZeroProtocol", from_checksum: Optional[str] = None
):
    """Requests all the events which occurred after from_checksum"""

    await du.expect_acknowledgement()
    du.reply(LatestChecksumPacket(checksum=from_checksum))
    return await du.expect(list[Signed[VNTEventPacket]])


@register_response(DialogueEnum.REQUEST_MISSING_EVENTS)
async def request_missing_events_response(du: DialogueUtil, protocol: "ZeroProtocol"):
    du.acknowledge()
    from_checksum = await du.expect(LatestChecksumPacket)
    from_checksum = from_checksum.checksum
    vnt = protocol.verification_net_timeline

    if from_checksum is not None:
        matched = vnt.from_checksum(from_checksum)
        if matched is None:
            raise DialogueException("Invalid dialogue state")
        events = list(event.get_packet() for event in vnt.iter_from(matched))
    else:
        events = list(event.get_packet() for event in vnt)
    du.reply(events)
    return events


@register_init(DialogueEnum.SEND_MISSING_EVENTS)
async def send_missing_events(
    du: DialogueUtil, protocol: "ZeroProtocol", from_checksum: Optional[str]
):
    """Sends all the events which occurred after from_checksum"""

    await du.expect_acknowledgement()
    vnt = protocol.verification_net_timeline
    if from_checksum is not None:
        matched = vnt.from_checksum(from_checksum)
        assert matched
        events = list(event.get_packet() for event in vnt.iter_from(matched))
    else:
        events = list(event.get_packet() for event in vnt)

    du.reply(events)
    return events


@register_response(DialogueEnum.SEND_MISSING_EVENTS)
async def send_missing_events_response(du: DialogueUtil, protocol: "ZeroProtocol"):
    du.acknowledge()
    events = await du.expect(list[Signed[VNTEventPacket]])
    protocol.verification_net_timeline.add_from_packets(events)


@register_init(DialogueEnum.SYNC_VNT)
async def sync_vnt(du: DialogueUtil, protocol: "ZeroProtocol"):
    """Syncs this nodes vnt with another nodes vnt so that both nodes have all the events
    up to cutoff"""

    await du.expect_acknowledgement()
    same_vnt = await check_same_vnt(du, protocol)
    if same_vnt:
        du.reply(ControlPacket.SUCCESS)
        return
    du.reply(ControlPacket.FAILURE)
    await du.expect_acknowledgement()

    latest_checksum = await find_latest_checksum(du, protocol)
    events = await request_missing_events(du, protocol, from_checksum=latest_checksum)
    # Doing this is fine even with an empty event timeline as the standard protocol would ship with a basic event timeline
    # baked in and would never have an empty event timeline in the first place. See main.py/initialize_network() for more details
    await send_missing_events(du, protocol, from_checksum=latest_checksum)
    protocol.verification_net_timeline.add_from_packets(events)

    res = await check_same_vnt(du, protocol)
    if not res:
        raise DialogueException("Couldn't sync VNT")


@register_response(DialogueEnum.SYNC_VNT)
async def sync_vnt_response(du: DialogueUtil, protocol: "ZeroProtocol"):
    du.acknowledge()
    await check_same_vnt_response(du, protocol)
    res = await du.expect(ControlPacket)
    du.acknowledge()
    if res == ControlPacket.SUCCESS:
        return
    await find_latest_checksum_response(du, protocol)
    await request_missing_events_response(du, protocol)
    await send_missing_events_response(du, protocol)
    await check_same_vnt_response(du, protocol)


@register_init(DialogueEnum.REQUEST_HOLD_RECEIPT)
async def request_hold_receipt(
    du: DialogueUtil, protocol: "ZeroProtocol", receipt: Signed[Receipt]
):
    """Requests a node to hold the receipt for a transaction that just occurred"""

    await du.expect_acknowledgement()
    du.reply(receipt)
    await du.expect_acknowledgement()


@register_init(DialogueEnum.TRANSFER_CREDIT)
async def transfer_credit(
    du: DialogueUtil, protocol: "ZeroProtocol", amount: int, payee: NodeData
):
    """Send currency to another wallet"""

    timestamp = cur_time()
    checksum = protocol.verification_net_timeline.get_latest_checksum()
    seed = RNGSeed(
        checksum=checksum,
        payee_public_key=payee.public_key,
        payer_public_key=protocol.public_key,
    )

    await du.expect_acknowledgement()

    # Helper function to sync missing events
    async def get_missing_events(witness: SelectedNode) -> list[Signed[VNTEventPacket]]:
        wdu = witness.dialogue_util()
        latest_checksum = await find_latest_checksum(wdu, protocol)

        if latest_checksum is None:
            raise DialogueException("Couldn't sync VNT")

        latest = protocol.verification_net_timeline.latest()
        assert latest is not None

        if latest_checksum == latest.checksum:
            return []

        missing = await request_missing_events(wdu, protocol, latest_checksum)
        return missing

    while True:
        # Reach out to witnesses
        witness_obj, _ = await select_witnesses(
            protocol, protocol.verification_net_timeline, timestamp, seed
        )
        witnesses = witness_obj.witnesses

        # Gather missing events
        results = await asyncio.gather(
            *(get_missing_events(witness) for witness in witnesses),
            return_exceptions=True
        )
        witness_obj.close_all_connections()
        filtered_results = filter(filter_exceptions, results)
        missing_events = set(event for events in filtered_results for event in events)

        # If no missing events before the cutoff then we have the right witnesses
        if not missing_events:
            # Make sure we're synced up with payee

            if await check_same_vnt(du, protocol):
                du.reply(ControlPacket.SUCCESS)
                break
            du.reply(ControlPacket.FAILURE)
            await du.expect_acknowledgement()
            await sync_vnt(du, protocol)

    witness_nodes = tuple(witness.node for witness in witnesses)

    # Create and send contract
    contract = Transaction(
        uuid=uuid.uuid4(),
        contract_type=ContractType.TRANSACTION,
        payer_address=protocol.address,
        payer_public_key=protocol.public_key,
        payee_address=payee.address,
        payee_public_key=payee.public_key,
        amount=amount,
        funds=(),
        witnesses=witness_nodes,
        timestamp=timestamp,
    )

    signed_contract = protocol.sign(contract)

    await du.expect_acknowledgement()
    du.reply(signed_contract)

    countersigned_contract = await du.expect(
        Signed[Transaction]
    )  # Signed by N0 so we don't need any additional signatures
    if not signed_contract.same_as(countersigned_contract):
        raise DialogueException("Unrecognized contract")

    receipt = Receipt(**vars(countersigned_contract))
    du.reply(receipt)  # Payment officially sent
    await du.expect_acknowledgement()


@register_init(DialogueEnum.INFORM_VNT_EVENT)
async def inform_vnt_event(
    du: DialogueUtil,
    protocol: "ZeroProtocol",
    signed_event_packet: Signed[VNTEventPacket],
):
    await du.expect_acknowledgement()
    du.reply(signed_event_packet)


@register_response(DialogueEnum.INFORM_VNT_EVENT)
async def inform_vnt_event_response(du: DialogueUtil, protocol: "ZeroProtocol"):
    du.acknowledge()
    signed_event_packet = await du.expect(Signed[VNTEventPacket])
    event = VNTEventFactory.event_from_packet(signed_event_packet)
    event.validate(protocol.verification_net_timeline)
    protocol.verification_net_timeline.add(event)
