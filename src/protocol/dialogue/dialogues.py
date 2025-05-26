import asyncio
import random
import secrets
import uuid
from typing import TYPE_CHECKING, Any, Coroutine, Optional

from crypto.signature import Signature, Signed
from network_emulator import network
from network_emulator.network_exceptions import NetworkException
from protocol.credit.credit_types import ContractType, Receipt, Stake, Transaction
from protocol.dialogue.const import ControlPacket, DialogueEnum
from protocol.dialogue.dialogue_registry import DialogueType, dialogue_registrars
from protocol.dialogue.dialogue_types import DialogueException
from protocol.dialogue.packets import LatestChecksumPacket, Nullable
from protocol.dialogue.util.contact_util import (
    contact_all_verification_nodes,
    filter_exceptions,
    gather_responses,
)
from protocol.dialogue.util.dialogue_util import DialogueUtil
from protocol.dialogue.util.rng_seed import RNGSeed
from protocol.dialogue.util.witness_selection_util import (
    SelectedNode,
    select_witnesses,
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
    MIN_CONNECTIONS,
    NODE_0_PUBLIC_KEY,
    STAKE_AMOUNT,
    TIME_TO_CONSISTENCY,
    VERIFIER_REDUNDANCY,
)
from timeline import cur_time

if TYPE_CHECKING:
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
        contract.validate_selected_witnesses(protocol)

    relevant_funds = (
        fund for fund in contract.funds if fund.witnessed_by(protocol.public_key)
    )

    for fund in relevant_funds:
        receipt_id = fund.receipt_id
        if receipt_id not in protocol.receipt_book:
            raise DialogueException("No record of receipt")

        tracked_fund = protocol.receipt_book[receipt_id]
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

    du.reply(protocol.sf.get_signature(receipt))


@register_init(DialogueEnum.RECONFIRM_TRANSACTION)
async def reconfirm_transaction(
    du: DialogueUtil, protocol: "StdProtocol", signed_receipt: Signed[Receipt]
) -> Signature:
    # We need to reconfirm the transaction to ensure that every witness has seen a copy signed by every witness. This means
    # that any deviant protocols attempting to cooperate must risk their stake if even a single node chooses to defect.
    await du.expect_acknowledgement()
    du.reply(signed_receipt)
    sig = await du.expect(Signature)
    sig.validate(signed_receipt)
    return sig


@register_response(DialogueEnum.RECONFIRM_TRANSACTION)
async def reconfirm_transaction_response(du: DialogueUtil, protocol: "StdProtocol"):
    du.acknowledge()
    signed_receipt = await du.expect(Signed[Receipt])
    receipt = signed_receipt.message
    receipt.validate_signatures()
    validation_flag = not receipt.signed_by_N0()

    if validation_flag:
        if not receipt.signed_by(protocol.public_key):
            raise DialogueException("Missing own signature")
        relevant_sigs = set(
            sig
            for sig in signed_receipt.signatures
            for witness in receipt.message.witnesses
            if witness.public_key == sig.public_key
        )
        if len(relevant_sigs) < VERIFIER_REDUNDANCY:
            raise DialogueException("Not enough signatures")

    # TODO make it possible to claim the stake from other witnesses by providing signed contracts in excess of available funds

    relevant_funds = (
        fund
        for fund in receipt.contract.funds
        if fund.receipt_id in protocol.receipt_book
    )

    for fund in relevant_funds:
        protocol.receipt_book.update_credit(fund, receipt)

    du.reply(protocol.sf.get_signature(signed_receipt))


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

    relevant_signatures = set(
        sig
        for sig in signed_receipt.signatures
        for witness in signed_receipt.message.contract.witnesses
        if sig.public_key == witness.public_key
    )
    if len(relevant_signatures) < VERIFIER_REDUNDANCY:
        if not validation_flag:
            raise DialogueException("Not enough signatures")

    signed_receipt.validate_signatures()
    receipt = signed_receipt.message

    if not receipt.contract.witnessed_by(protocol.public_key):
        raise DialogueException("Not a witness for this transaction")

    receipt.validate_signatures()
    protocol.receipt_book.add(receipt)

    du.acknowledge()


@register_init(DialogueEnum.TRANSFER_CREDIT)
async def transfer_credit(
    du: DialogueUtil, protocol: "StdProtocol", amount: int, payee: NodeData
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
        witness_obj, skipped = await select_witnesses(
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

    # Run stat tests on selected witnesses to make sure the selected witnesses are valid
    validate_skips(skipped)
    witness_nodes = tuple(witness.node for witness in witnesses)

    # Get collected sources of funds to be transferred
    wallet = protocol.wallet

    try:
        funds = wallet.find_funds(amount, protocol.verification_net_timeline)
    except ValueError as e:
        raise DialogueException("Not enough funds to cover transfer")

    for fund in funds:
        fund.validate_missing_events(protocol)

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
        witnesses=witness_nodes,
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
    protocol.wallet.update_credit(receipt)
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
    signed_contract = await du.expect(
        Signed[Transaction]
    )  # TODO test if this actually works with generics or not
    signed_contract.validate_signatures()
    validation_flag = not signed_contract.signed_by_N0()
    contract = signed_contract.message

    if validation_flag:
        contract.validate_funds(protocol)
        contract.validate_selected_witnesses(protocol)

    countersigned_contract = protocol.sign(contract)
    du.reply(countersigned_contract)
    receipt = await du.expect(Receipt)  # Fully signed contract.

    receipt.validate_signatures()
    validation_flag = not receipt.signed_by_N0()

    if validation_flag:
        if not receipt.same_as(signed_contract):
            raise DialogueException("Unrecognized contract")

        # Verify that enough witnesses have signed and validate signatures
        for fund in receipt.contract.funds:
            signature_count = 0
            for witness in fund.witnesses:
                if receipt.signed_by(witness.public_key):
                    signature_count += 1

            if signature_count < VERIFIER_REDUNDANCY:
                raise DialogueException(
                    "Invalid contract, not enough signatures for fund"
                )

    du.acknowledge()  # Payment is considered sent at this point.

    # Anything beyond this point can be done at a later time. The payment is already received we just need to notify the old / new witnesses.

    final_contract = receipt.contract

    async def connect_to_witness(witness: VerificationNodeData) -> DialogueUtil:
        nc = await network.connect(protocol.address, witness.address)
        return DialogueUtil(nc)

    async def get_witness_signature(connection: DialogueUtil):
        return await confirm_transaction(connection, protocol, receipt)

    connections = await asyncio.gather(
        *(connect_to_witness(witness) for witness in final_contract.witnesses),
        return_exceptions=True
    )
    connections = tuple(filter(filter_exceptions, connections))
    signatures = await asyncio.gather(
        *(get_witness_signature(wdu) for wdu in connections), return_exceptions=True
    )
    signatures = frozenset(filter(filter_exceptions, signatures))
    signed_receipt = Signed(message=receipt, signatures=signatures)

    async def get_final_signature(connection: DialogueUtil):
        return await reconfirm_transaction(connection, protocol, signed_receipt)

    signatures = await asyncio.gather(
        *(get_final_signature(wdu) for wdu in connections), return_exceptions=True
    )
    signatures = frozenset(filter(filter_exceptions, signatures))
    signed_signed_receipt = Signed(message=signed_receipt, signatures=signatures)

    if len(signed_signed_receipt.signatures) < VERIFIER_REDUNDANCY:
        raise DialogueException("Not enough responses confirming transaction")

    await asyncio.gather(
        *(
            request_hold_receipt(connection, protocol, signed_receipt)
            for connection in connections
        ),
        return_exceptions=True
    )
    protocol.wallet.update_credit(receipt)


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
        stake.validate_funds(protocol.verification_net_timeline)

    for fund in stake.funds:
        if not fund.witnessed_by(protocol.public_key):
            continue

        if fund.receipt_id not in protocol.receipt_book:
            raise DialogueException("No record of receipt")

        tracked_fund = protocol.receipt_book[fund.receipt_id]
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
        relevant_signatories = set(
            sig.public_key
            for sig in signatures
            if sig.public_key in (witness.public_key for witness in fund.witnesses)
        )

        if len(relevant_signatories) < VERIFIER_REDUNDANCY:
            raise DialogueException("Not enough signatures on fund for stake")

    # You're able to get the rest of the signatures later if you don't have enough
    # TODO: Make it so you can release your stake if you never join the verification net (delay until eventual consistency same as leaving verification net)

    signed_stake = Signed(message=stake, signatures=signatures)
    join_data = JoinData(signed_stake, stake.timestamp)
    event_packet = VNTEventFactory.packet_from_data(
        VerificationNetEventEnum.NODE_JOIN, join_data
    )
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
    fund_ids = tuple(fund.receipt_id for fund in stake.funds)
    leave_data = LeaveData(stake.uuid, witnesses, fund_ids, timestamp, stake.get_node())
    event_packet = VNTEventFactory.packet_from_data(
        VerificationNetEventEnum.NODE_LEAVE, leave_data
    )
    event_packet = protocol.sign(event_packet)
    leave_event = VNTEventFactory.event_from_packet(event_packet)
    protocol.verification_net_timeline.add(leave_event)

    def release_stake():
        for fund_withdrawal in stake.funds:
            fund = protocol.wallet.get_fund(fund_withdrawal.receipt_id)
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
    pause_data = PauseData(timestamp, node_data)
    event_packet = VNTEventFactory.packet_from_data(
        VerificationNetEventEnum.NODE_PAUSE, pause_data
    )
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
    resume_data = ResumeData(timestamp, node_data)
    event_packet = VNTEventFactory.packet_from_data(
        VerificationNetEventEnum.NODE_RESUME, resume_data
    )
    event_packet = protocol.sign(event_packet)
    resume_event = VNTEventFactory.event_from_packet(event_packet)
    protocol.verification_net_timeline.add(resume_event)
    await contact_all_verification_nodes(
        protocol, protocol.verification_net_timeline, inform_vnt_event, event_packet
    )


async def add_entropy(protocol: "StdProtocol"):
    timestamp = cur_time()
    node_data = protocol.verification_node_data()
    entropy_data = EntropyData(timestamp, node_data, secrets.token_hex())
    event_packet = VNTEventFactory.packet_from_data(
        VerificationNetEventEnum.ADD_ENTROPY, entropy_data
    )
    event_packet = protocol.sign(event_packet)
    entropy_event = VNTEventFactory.event_from_packet(event_packet)
    protocol.verification_net_timeline.add(entropy_event)
    await contact_all_verification_nodes(
        protocol, protocol.verification_net_timeline, inform_vnt_event, event_packet
    )


# TODO
# Rollover.
# Witnesses get cut of contract, gas for witnesses.
# Get stake from fraudulent contract and contracts proving funds already ran out.
