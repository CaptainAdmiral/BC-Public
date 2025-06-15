import asyncio
import random
import secrets
import uuid
from typing import TYPE_CHECKING, Any, Coroutine, Optional

from crypto.signature import Signature, Signed, with_signatures
from network_emulator import network
from network_emulator.network_exceptions import NetworkException
from protocol.credit.credit_types import ContractType, Receipt, Stake, Transaction
from protocol.dialogue.const import ControlPacket, DialogueEnum
from protocol.dialogue.dialogue_registry import DialogueType, dialogue_registrars
from protocol.dialogue.dialogue_types import DialogueException
from protocol.dialogue.packets import (
    LatestChecksumPacket,
    Nullable,
    RolloverPacket,
    TrackedFundPacket,
)
from protocol.dialogue.util.contact_util import (
    contact_all_verification_nodes,
    filter_exceptions,
    gather_responses,
)
from protocol.dialogue.util.dialogue_util import DialogueUtil
from protocol.dialogue.util.rng_seed import RNGSeed, get_transaction_rng
from protocol.dialogue.util.witness_selection_util import (
    SelectedNode,
    SelectedWitnesses,
    select_witnesses,
    validate_signature_count,
    validate_skips,
)
from protocol.protocols.abstract_protocol import AbstractProtocol
from protocol.protocols.common_types import NodeData, VerificationNodeData
from protocol.verification_net.vnt_event_factory import VNTEventFactory
from protocol.verification_net.vnt_types import (
    EntropyData,
    JoinData,
    LeaveData,
    PauseData,
    ResumeData,
    VerificationNetEventEnum,
    VNTEventPacket,
)
from settings import (
    ACTIVE_RATIO,
    GAS_AMOUNT,
    MIN_CONNECTIONS,
    NODE_0_PUBLIC_KEY,
    ROLLOVER_PERIOD,
    STAKE_AMOUNT,
    TIME_TO_CONSISTENCY,
    TIMESTAMP_LENIENCY,
    VERIFIER_REDUNDANCY,
)
from timeline import cur_time

if TYPE_CHECKING:
    from protocol.credit.tracked_fund import TrackedFund
    from protocol.protocols.std_protocol.std_protocol import StdProtocol


DIALOGUES: dict[str, DialogueType] = {}
RESPONSES: dict[str, DialogueType] = {}
register_init, register_response = dialogue_registrars(DIALOGUES, RESPONSES)


@register_init(DialogueEnum.HANDSHAKE)
async def handshake(du: DialogueUtil, protocol: "AbstractProtocol"):
    await du.expect_acknowledgement()


@register_response(DialogueEnum.HANDSHAKE)
async def handshake_response(du: DialogueUtil, protocol: "AbstractProtocol"):
    du.acknowledge()


@register_init(DialogueEnum.CHECK_SAME_VNT)
async def check_same_vnt(
    du: DialogueUtil, protocol: "StdProtocol", cutoff: Optional[float] = None
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
async def check_same_vnt_response(du: DialogueUtil, protocol: "StdProtocol"):
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


@register_init(DialogueEnum.REQUEST_ADD_SELF)
async def request_add_self(du: DialogueUtil, protocol: "StdProtocol"):
    """Request that another node adds this node to it's node list"""

    await du.expect_acknowledgement()
    du.reply(protocol.node_data)


@register_response(DialogueEnum.REQUEST_ADD_SELF)
async def request_add_self_response(du: DialogueUtil, protocol: "StdProtocol"):
    du.acknowledge()
    packet = await du.expect(NodeData)
    protocol.node_list.append(packet)


@register_init(DialogueEnum.REQUEST_NODE_LIST)
async def request_node_list(du: DialogueUtil, protocol: "StdProtocol"):
    """Requests a big enough random subset of the node list from another node to ensure enough redundant connections"""

    node_list = await du.expect(list[NodeData])
    results = await gather_responses(
        protocol, request_add_self, node_list, MIN_CONNECTIONS
    )
    protocol.node_list.extend(res.node for res in results)


@register_response(DialogueEnum.REQUEST_NODE_LIST)
async def request_node_list_response(du: DialogueUtil, protocol: "StdProtocol"):
    node_list = random.sample(
        protocol.node_list, int(2 * MIN_CONNECTIONS / ACTIVE_RATIO)
    )
    du.reply(node_list)


@register_init(DialogueEnum.GET_LATEST_HASH)
async def find_latest_checksum(du: DialogueUtil, protocol: "StdProtocol") -> str | None:
    """Finds the latest checksum shared between this node and another node,
    which is exactly the point the two verification timelines start to differ"""

    await du.expect_acknowledgement()
    same_vnt = await check_same_vnt(du, protocol)
    if same_vnt:
        latest = protocol.verification_net_timeline.latest()
        assert latest is not None
        du.reply(ControlPacket.SUCCESS)
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
    du: DialogueUtil, protocol: "StdProtocol"
) -> str | None:
    du.acknowledge()
    await check_same_vnt_response(du, protocol)
    success_packet = await du.expect(ControlPacket)
    if success_packet == ControlPacket.SUCCESS:
        return
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
    du: DialogueUtil, protocol: "StdProtocol", from_checksum: Optional[str] = None
):
    """Requests all the events which occurred after from_checksum"""

    await du.expect_acknowledgement()
    du.reply(LatestChecksumPacket(checksum=from_checksum))
    return await du.expect(list[Signed[VNTEventPacket]])


@register_response(DialogueEnum.REQUEST_MISSING_EVENTS)
async def request_missing_events_response(du: DialogueUtil, protocol: "StdProtocol"):
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
    du: DialogueUtil, protocol: "StdProtocol", from_checksum: Optional[str]
):
    """Sends all the events which occurred after from_checksum"""

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
async def send_missing_events_response(du: DialogueUtil, protocol: "StdProtocol"):
    du.acknowledge()
    events = await du.expect(list[Signed[VNTEventPacket]])
    protocol.verification_net_timeline.add_from_packets(events)


@register_init(DialogueEnum.SYNC_VNT)
async def sync_vnt(du: DialogueUtil, protocol: "StdProtocol"):
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
async def sync_vnt_response(du: DialogueUtil, protocol: "StdProtocol"):
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


@register_init(DialogueEnum.REQUEST_WITNESS_SIGNATURE)
async def request_signature(
    du: DialogueUtil, protocol: "StdProtocol", contract: Signed[Transaction]
) -> Signature:
    """Checks with a fund witness if there is enough credit remaining in the fund to cover the requested amount"""

    await du.expect_acknowledgement()
    du.reply(contract)
    return await du.expect(Signature)


@register_response(DialogueEnum.REQUEST_WITNESS_SIGNATURE)
async def request_signature_response(du: DialogueUtil, protocol: "StdProtocol"):
    du.acknowledge()
    signed_contract = await du.expect(Signed[Transaction])
    signed_contract.validate_signatures()
    validation_flag = not signed_contract.signed_by_N0()

    contract = signed_contract.message
    if validation_flag:
        current_time = cur_time()
        if abs(contract.timestamp - current_time) > TIMESTAMP_LENIENCY:
            raise DialogueException(
                f"Invalid timestamp, timestamp {contract.timestamp} and cur time {current_time} must be within {TIMESTAMP_LENIENCY}"
            )

    relevant_funds = (
        fund for fund in contract.funds if fund.witnessed_by(protocol.public_key)
    )

    for fund in relevant_funds:
        receipt_id = fund.fund_id
        if receipt_id not in protocol.receipt_book:
            raise DialogueException("No record of receipt")

        tracked_fund = protocol.receipt_book[receipt_id]
        tracked_fund.validate_expiry()
        if tracked_fund.available < fund.amount:
            raise DialogueException("Insufficient funds remaining")

    du.reply(protocol.sf.get_signature(contract))


@register_init(DialogueEnum.CONFIRM_TRANSACTION)
async def confirm_transaction(
    du: DialogueUtil, protocol: "StdProtocol", receipt: Receipt
) -> Signature:
    """Gets a signed confirmation that a witness has received the final transaction contract and updated the funds used for that transaction"""

    await du.expect_acknowledgement()
    du.reply(receipt)
    sig = await du.expect(Signature)
    sig.validate(receipt)
    return sig


@register_response(DialogueEnum.CONFIRM_TRANSACTION)
async def confirm_transaction_response(du: DialogueUtil, protocol: "StdProtocol"):
    du.acknowledge()
    receipt = await du.expect(Receipt)
    receipt.validate_signatures()
    validation_flag = not receipt.signed_by_N0()

    if validation_flag:
        if not receipt.signed_by(protocol.public_key):
            raise DialogueException("Missing own signature")
        validate_signature_count(receipt.witnesses, receipt.signatures)

    # TODO make it possible to claim the stake from other witnesses by providing signed contracts in excess of available funds
    relevant_funds = (
        fund for fund in receipt.contract.funds if fund.fund_id in protocol.receipt_book
    )

    for fund in relevant_funds:
        protocol.receipt_book.update_credit(fund, receipt, protocol.wallet)

    du.reply(protocol.sf.get_signature(receipt))


@register_init(DialogueEnum.REQUEST_HOLD_RECEIPT)
async def request_hold_receipt(
    du: DialogueUtil, protocol: "StdProtocol", receipt: Signed[Receipt]
):
    """Requests a node to hold the receipt for a transaction that just occurred"""

    await du.expect_acknowledgement()
    du.reply(receipt)
    await du.expect_acknowledgement()


@register_response(DialogueEnum.REQUEST_HOLD_RECEIPT)
async def request_hold_receipt_response(du: DialogueUtil, protocol: "StdProtocol"):
    du.acknowledge()
    signed_receipt = await du.expect(Signed[Receipt])

    validation_flag = not signed_receipt.signed_by_N0

    if validation_flag:
        signed_receipt.message.validate_expiry()
        validate_signature_count(
            signed_receipt.message.witnesses, signed_receipt.signatures
        )

    signed_receipt.validate_signatures()
    receipt = signed_receipt.message

    if not receipt.witnessed_by(protocol.public_key):
        raise DialogueException("Not a witness for this transaction")

    receipt.validate_signatures()
    protocol.receipt_book.add(receipt)
    protocol.schedule_event(
        receipt.contract.timestamp + ROLLOVER_PERIOD * 2,
        lambda: protocol.receipt_book.drop_fund(receipt.id, protocol.wallet),
    )

    du.acknowledge()


async def get_up_to_date_witnesses(
    protocol: "StdProtocol",
    timestamp: float,
    seed: RNGSeed,
    synced_du: Optional[DialogueUtil] = None,
) -> SelectedWitnesses:

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
        witness_obj, skipped = await select_witnesses(
            protocol, protocol.verification_net_timeline, timestamp, seed
        )

        witnesses = witness_obj.witnesses

        # Gather missing events
        results = await asyncio.gather(
            *(get_missing_events(witness) for witness in witnesses),
            return_exceptions=True,
        )

        witness_obj.close_all_connections()
        filtered_results = filter(filter_exceptions, results)
        missing_events = set(event for events in filtered_results for event in events)

        # If no missing events before the cutoff then we have the right witnesses
        if not missing_events:
            if synced_du is not None:
                # Make sure we're synced up with payee
                if await check_same_vnt(synced_du, protocol):
                    synced_du.reply(ControlPacket.SUCCESS)
                    break
                synced_du.reply(ControlPacket.FAILURE)
                await synced_du.expect_acknowledgement()
                await sync_vnt(synced_du, protocol)
            else:
                break

    # Run stat tests on selected witnesses to make sure the selected witnesses are valid
    validate_skips(skipped)
    return witness_obj


@register_init(DialogueEnum.TRANSFER_CREDIT)
async def transfer_credit(
    du: DialogueUtil, protocol: "StdProtocol", amount: int, payee: NodeData
):
    """Send currency to another wallet"""

    if amount <= GAS_AMOUNT:
        raise ValueError(f"Transaction amount must be greater than {GAS_AMOUNT}")

    timestamp = cur_time()
    seed = get_transaction_rng(
        vnt=protocol.verification_net_timeline,
        timestamp=timestamp,
        payee_public_key=payee.public_key,
        payer_public_key=protocol.public_key,
    )

    await du.expect_acknowledgement()

    witness_obj = await get_up_to_date_witnesses(protocol, timestamp, seed, du)
    witness_obj.close_all_connections()

    # Get collected sources of funds to be transferred
    wallet = protocol.wallet

    try:
        funds = wallet.find_funds(amount, protocol.verification_net_timeline)
    except ValueError as e:
        raise DialogueException("Not enough funds to cover transfer")

    for fund in funds:
        fund.validate_missing_events(protocol.verification_net_timeline)

    # Create and send contract
    initial_contract = Transaction(
        uuid=uuid.uuid4(),
        contract_type=ContractType.TRANSACTION,
        payer_address=protocol.address,
        payer_public_key=protocol.public_key,
        payee_address=payee.address,
        payee_public_key=payee.public_key,
        amount=amount,
        funds=tuple(funds),
        timestamp=timestamp,
    )

    signed_contract = protocol.sign(initial_contract)

    await du.expect_acknowledgement()
    du.reply(signed_contract)

    countersigned_contract = await du.expect(
        Signed[Transaction]
    )  # Signed by payer and payee but no witnesses yet
    if not signed_contract.same_as(countersigned_contract):
        raise DialogueException("Unrecognized contract")

    # Get signatures from all witnesses
    async def get_signature(
        witness: VerificationNodeData, contract: Signed[Transaction]
    ) -> Signature:
        nc = await network.connect(protocol.address, witness.address)
        wdu = DialogueUtil(nc)
        signature = await request_signature(wdu, protocol, contract)
        signature.validate(contract.message)
        return signature

    tasks: list[set[asyncio.Task[Signature]]] = []
    for withdrawal in funds:
        task_set: set[asyncio.Task[Signature]] = set()
        for witness in withdrawal.witnesses:
            task_set.add(
                asyncio.create_task(get_signature(witness, countersigned_contract))
            )
        if task_set:
            tasks.append(task_set)

    signatures: list[Signature] = []
    for task_set in tasks:
        sig_count = 0
        done, _ = await asyncio.wait(task_set)

        for finished_task in done:
            try:
                signature = finished_task.result()
                signatures.append(signature)
                sig_count += 1
            except (NetworkException, DialogueException) as e:
                ...

        if sig_count < VERIFIER_REDUNDANCY:
            if not NODE_0_PUBLIC_KEY in (sig.public_key for sig in signatures):
                raise DialogueException("Not enough signatures")

    # Validate witness signatures
    for sig in signatures:
        sig.validate(countersigned_contract.message)

    fully_signed_contract = countersigned_contract.with_signatures(
        *signatures
    )  # Signed by all witnesses as well
    receipt = Receipt(**vars(fully_signed_contract))
    du.reply(receipt)  # Payment officially sent
    protocol.wallet.deduct_credit(receipt)
    await du.expect_acknowledgement()


@register_response(DialogueEnum.TRANSFER_CREDIT)
async def transfer_credit_response(du: DialogueUtil, protocol: "StdProtocol"):
    du.acknowledge()
    await check_same_vnt_response(du, protocol)
    success_packet = await du.expect(ControlPacket)
    du.acknowledge()
    while success_packet != ControlPacket.SUCCESS:
        await sync_vnt_response(du, protocol)
        await check_same_vnt_response(du, protocol)
        success_packet = await du.expect(ControlPacket)
        du.acknowledge()

    # Initial contract
    signed_contract = await du.expect(Signed[Transaction])
    signed_contract.validate_signatures()
    validation_flag = not signed_contract.signed_by_N0()
    contract = signed_contract.message

    if validation_flag:
        if contract.amount <= GAS_AMOUNT:
            raise DialogueException(
                f"Transaction amount must be greater than {GAS_AMOUNT}"
            )
        current_time = cur_time()
        if abs(contract.timestamp - current_time) > TIMESTAMP_LENIENCY:
            raise DialogueException(
                f"Invalid timestamp, timestamp {contract.timestamp} and cur time {current_time} must be within {TIMESTAMP_LENIENCY}"
            )
        contract.validate_funds(protocol)

    countersigned_contract = protocol.sign(contract)
    du.reply(countersigned_contract)
    receipt = await du.expect(Receipt)  # Fully signed contract.

    receipt.validate_signatures()
    validation_flag = not receipt.signed_by_N0()

    if validation_flag:
        if not receipt.same_as(signed_contract):
            raise DialogueException("Unrecognized contract")

        receipt.validate_expiry()
        receipt.validate_selected_witnesses(protocol)

        for fund in receipt.contract.funds:
            validate_signature_count(fund.witnesses, receipt.signatures)

    du.acknowledge()  # Payment is considered sent at this point.

    # Anything beyond this point can be done at a later time. The payment is already received we just need to notify the old / new witnesses.

    final_contract = receipt.contract

    async def connect_to_witness(witness: VerificationNodeData) -> DialogueUtil:
        nc = await network.connect(protocol.address, witness.address)
        nc.open()
        return DialogueUtil(nc)

    async def get_witness_signature(connection: DialogueUtil):
        return await confirm_transaction(connection, protocol, receipt)

    witnesses = set(
        witness for fund in final_contract.funds for witness in fund.witnesses
    )

    connections = await asyncio.gather(
        *(connect_to_witness(witness) for witness in witnesses), return_exceptions=True
    )
    connections = tuple(filter(filter_exceptions, connections))

    try:
        signatures = await asyncio.gather(
            *(get_witness_signature(wdu) for wdu in connections), return_exceptions=True
        )
        signatures = frozenset(filter(filter_exceptions, signatures))

        for fund in final_contract.funds:
            validate_signature_count(fund.witnesses, signatures)

        signed_receipt = Signed(message=receipt, signatures=signatures)

    finally:
        for connection in connections:
            connection.net_connection.close()

    await distribute_receipt(du, protocol, signed_receipt)


async def distribute_receipt(
    du: DialogueUtil, protocol: "StdProtocol", signed_receipt: Signed[Receipt]
):
    receipt = signed_receipt.message

    async def connect_to_witness(witness: VerificationNodeData) -> DialogueUtil:
        nc = await network.connect(protocol.address, witness.address)
        nc.open()
        return DialogueUtil(nc)

    witness_connections = await asyncio.gather(
        *(connect_to_witness(witness) for witness in receipt.witnesses),
        return_exceptions=True,
    )
    witness_connections = tuple(filter(filter_exceptions, witness_connections))
    try:
        await asyncio.gather(
            *(
                request_hold_receipt(connection, protocol, signed_receipt)
                for connection in witness_connections
            ),
            return_exceptions=True,
        )
        protocol.wallet.add_credit(receipt)

    finally:
        for connection in witness_connections:
            connection.net_connection.close()


@register_init(DialogueEnum.CONFIRM_STAKE)
async def confirm_stake(
    du: DialogueUtil, protocol: "StdProtocol", signed_stake: Signed[Stake]
):
    """Get's a signature confirming that the stake has been reserved for the relevant funds"""

    await du.expect_acknowledgement()
    du.reply(signed_stake)
    return await du.expect(Signature)


@register_response(DialogueEnum.CONFIRM_STAKE)
async def confirm_stake_response(du: DialogueUtil, protocol: "StdProtocol"):
    signed_stake = await du.expect(Signed[Stake])
    signed_stake.validate_signatures()
    validation_flag = not signed_stake.signed_by_N0()
    stake = signed_stake.message

    if validation_flag:
        stake.validate_funds(protocol.verification_net_timeline, stake.timestamp)

    for fund in stake.funds:
        if not fund.witnessed_by(protocol.public_key):
            continue

        if fund.fund_id not in protocol.receipt_book:
            raise DialogueException("No record of receipt")

        tracked_fund = protocol.receipt_book[fund.fund_id]
        if tracked_fund.available < fund.amount:
            raise DialogueException("Not enough credit available to cover fund")
        tracked_fund.reserve_credit(stake)

    signature = protocol.sf.get_signature(stake)
    du.reply(signature)

    du.acknowledge()


@register_init(DialogueEnum.INFORM_VNT_EVENT)
async def inform_vnt_event(
    du: DialogueUtil,
    protocol: "StdProtocol",
    signed_event_packet: Signed[VNTEventPacket],
):
    await du.expect_acknowledgement()
    du.reply(signed_event_packet)


@register_response(DialogueEnum.INFORM_VNT_EVENT)
async def inform_vnt_event_response(du: DialogueUtil, protocol: "StdProtocol"):
    du.acknowledge()
    signed_event_packet = await du.expect(Signed[VNTEventPacket])
    event = VNTEventFactory.event_from_packet(signed_event_packet)
    event.validate(protocol.verification_net_timeline)
    protocol.verification_net_timeline.add(event)


async def join_verification_net(protocol: "StdProtocol"):
    timestamp = cur_time()
    funds = protocol.wallet.find_funds(STAKE_AMOUNT, protocol.verification_net_timeline)

    stake = Stake(
        uuid=uuid.uuid4(),
        contract_type=ContractType.STAKE,
        address=protocol.address,
        public_key=protocol.public_key,
        amount=STAKE_AMOUNT,
        funds=tuple(funds),
        timestamp=timestamp,
    )

    signed_stake = protocol.sign(stake)

    async def get_signature(witness: VerificationNodeData) -> Signature:
        nc = await network.connect(protocol.address, witness.address)
        wdu = DialogueUtil(nc)
        signature = await confirm_stake(wdu, protocol, signed_stake)
        signature.validate(stake)
        return signature

    signature_cr: set[Coroutine[Any, Any, Signature]] = set()
    for fund in funds:
        for witness in fund.witnesses:
            signature_cr.add(get_signature(witness))

    signatures = await asyncio.gather(*signature_cr, return_exceptions=True)
    signatures = frozenset(filter(filter_exceptions, signatures))

    for fund in stake.funds:
        validate_signature_count(fund.witnesses, signatures)

    # You're able to get the rest of the signatures later if you don't have enough
    # TODO: Make it so you can release your stake if you never join the verification net (delay until eventual consistency same as leaving verification net)

    signed_stake = Signed(message=stake, signatures=signatures)
    join_data = JoinData(
        VerificationNetEventEnum.NODE_JOIN, signed_stake, stake.timestamp
    )
    event_packet = VNTEventPacket(join_data)
    event_packet = protocol.sign(event_packet)
    join_event = VNTEventFactory.event_from_packet(event_packet)
    protocol.verification_net_timeline.add(join_event)
    protocol.stake = stake
    await contact_all_verification_nodes(
        protocol, protocol.verification_net_timeline, inform_vnt_event, event_packet
    )


async def leave_verification_net(protocol: "StdProtocol"):
    timestamp = cur_time()

    stake = protocol.stake
    assert stake is not None

    witnesses = tuple(
        set(witness for fund in stake.funds for witness in fund.witnesses)
    )
    fund_ids = tuple(fund.fund_id for fund in stake.funds)
    leave_data = LeaveData(
        VerificationNetEventEnum.NODE_LEAVE,
        stake.uuid,
        witnesses,
        fund_ids,
        timestamp,
        stake.get_node(),
    )
    event_packet = VNTEventPacket(leave_data)
    event_packet = protocol.sign(event_packet)
    leave_event = VNTEventFactory.event_from_packet(event_packet)
    protocol.verification_net_timeline.add(leave_event)

    def release_stake():
        for fund_withdrawal in stake.funds:
            fund = protocol.wallet.get_fund(fund_withdrawal.fund_id)
            fund.release_credit(stake.uuid)
        protocol.stake = None

    protocol.schedule_event(timestamp + TIME_TO_CONSISTENCY, release_stake)
    await contact_all_verification_nodes(
        protocol, protocol.verification_net_timeline, inform_vnt_event, event_packet
    )


async def pause_verification(protocol: "StdProtocol"):
    timestamp = cur_time()
    assert protocol.stake

    node_data = protocol.verification_node_data()
    pause_data = PauseData(VerificationNetEventEnum.NODE_PAUSE, timestamp, node_data)
    event_packet = VNTEventPacket(pause_data)
    event_packet = protocol.sign(event_packet)
    pause_event = VNTEventFactory.event_from_packet(event_packet)
    protocol.verification_net_timeline.add(pause_event)
    await contact_all_verification_nodes(
        protocol, protocol.verification_net_timeline, inform_vnt_event, event_packet
    )


async def resume_verification(protocol: "StdProtocol"):
    timestamp = cur_time()
    assert protocol.stake

    node_data = protocol.verification_node_data()
    resume_data = ResumeData(VerificationNetEventEnum.NODE_RESUME, timestamp, node_data)
    event_packet = VNTEventPacket(resume_data)
    event_packet = protocol.sign(event_packet)
    resume_event = VNTEventFactory.event_from_packet(event_packet)
    protocol.verification_net_timeline.add(resume_event)
    await contact_all_verification_nodes(
        protocol, protocol.verification_net_timeline, inform_vnt_event, event_packet
    )


async def add_entropy(protocol: "StdProtocol"):
    timestamp = cur_time()
    node_data = protocol.verification_node_data()
    entropy_data = EntropyData(
        VerificationNetEventEnum.ADD_ENTROPY, timestamp, node_data, secrets.token_hex()
    )
    event_packet = VNTEventPacket(entropy_data)
    event_packet = protocol.sign(event_packet)
    entropy_event = VNTEventFactory.event_from_packet(event_packet)
    protocol.verification_net_timeline.add(entropy_event)
    await contact_all_verification_nodes(
        protocol, protocol.verification_net_timeline, inform_vnt_event, event_packet
    )


@register_init(DialogueEnum.REQUEST_ROLLOVER_SIGNATURE)
async def request_rollover_signature(
    du: DialogueUtil, protocol: "StdProtocol", fund_packet: TrackedFundPacket
) -> Signature:
    """Requests a signature confirming that no transactions are missing from the tracked fund"""

    await du.expect_acknowledgement()
    du.reply(fund_packet)
    return await du.expect(Signature)


@register_response(DialogueEnum.REQUEST_ROLLOVER_SIGNATURE)
async def request_rollover_signature_response(
    du: DialogueUtil, protocol: "StdProtocol"
):
    du.acknowledge()
    fund_packet = await du.expect(TrackedFundPacket)
    fund_details = fund_packet.details

    if fund_details.id not in protocol.receipt_book:
        raise DialogueException("Not a witness for this transaction")

    if fund_details.timestamp + ROLLOVER_PERIOD < cur_time() + TIMESTAMP_LENIENCY:
        raise DialogueException("Too soon for rollover")

    own_tracked_fund = protocol.receipt_book[fund_details.id]
    own_tracked_withdrawals = set(own_tracked_fund.withdrawals)
    claimed_withdrawals = set(fund_packet.withdrawals)
    undeclared_withdrawals = own_tracked_withdrawals - claimed_withdrawals
    if undeclared_withdrawals:
        raise DialogueException("Undeclared withdrawals on rollover")

    own_tracked_reservations = set(own_tracked_fund.reservations)
    claimed_reservations = set(fund_packet.reservations)
    undeclared_reservations = own_tracked_reservations - claimed_reservations
    if undeclared_reservations:
        raise DialogueException("Undeclared reservations on rollover")

    du.reply(protocol.sf.get_signature(fund_packet))


@register_init(DialogueEnum.SEND_ROLLOVER_FUND)
async def send_rollover_fund(
    du: DialogueUtil,
    protocol: "StdProtocol",
    signed_fund: Signed[TrackedFundPacket],
    new_witnesses: tuple[VerificationNodeData, ...],
    new_witness_selection_time: float,
):
    """Sends a receipt (signed by old witnesses to confirm nothing is missing) to the new witnesses to hold for verification of funds"""

    await du.expect_acknowledgement()
    rollover_packet = RolloverPacket(
        signed_fund=signed_fund,
        new_witnesses=new_witnesses,
        witness_selection_time=new_witness_selection_time,
    )
    du.reply(rollover_packet)
    await du.expect_acknowledgement()


@register_response(DialogueEnum.SEND_ROLLOVER_FUND)
async def send_rollover_fund_response(du: DialogueUtil, protocol: "StdProtocol"):
    du.acknowledge()
    rollover_packet = await du.expect(RolloverPacket)
    signed_fund = rollover_packet.signed_fund
    new_witnesses = rollover_packet.new_witnesses
    witness_selection_time = rollover_packet.witness_selection_time
    old_receipt = signed_fund.message.details
    new_receipt = old_receipt.update_witnesses(new_witnesses, witness_selection_time)
    signed_fund.validate_signatures()
    validate_signature_count(old_receipt.witnesses, signed_fund.signatures)
    old_receipt.validate_selected_witnesses(protocol)
    new_receipt.validate_selected_witnesses(protocol)

    protocol.receipt_book.add(new_receipt)

    du.acknowledge()


async def rollover_fund_witnesses(protocol: "StdProtocol", fund: "TrackedFund"):
    timestamp = cur_time()
    old_fund_details = fund.details
    fund_packet = fund.to_packet()
    seed = fund.details.rng_seed

    async def get_old_signature(witness: VerificationNodeData) -> Signature:
        wnc = await network.connect(protocol.address, witness.address)
        wdu = DialogueUtil(wnc)
        sig = await request_rollover_signature(wdu, protocol, fund_packet)
        return sig

    signatures = await asyncio.gather(
        *(get_old_signature(witness) for witness in old_fund_details.witnesses)
    )
    signatures = filter(filter_exceptions, signatures)
    validate_signature_count(old_fund_details.witnesses, signatures)
    signed_fund_packet = with_signatures(fund_packet, signatures)

    send_to_new_witnesses_tasks: set[asyncio.Task] = set()
    witness_obj = await get_up_to_date_witnesses(protocol, timestamp, seed)
    witnesses = witness_obj.witnesses
    witness_nodes = tuple(witness.node for witness in witnesses)

    for witness in witness_obj.witnesses:
        wdu = DialogueUtil(witness.net_con)
        send_to_new_witnesses_tasks.add(
            asyncio.create_task(
                send_rollover_fund(
                    wdu, protocol, signed_fund_packet, witness_nodes, timestamp
                )
            )
        )

    witness_obj.close_all_connections()
    protocol.wallet[old_fund_details.id].update_after_rollover(witness_nodes, timestamp)


# TODO
# Get stake from fraudulent contract and contracts proving funds already ran out.
