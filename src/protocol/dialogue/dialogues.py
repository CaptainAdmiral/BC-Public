import asyncio
from collections import namedtuple
from dataclasses import dataclass
import time
import random
from typing import Any, Coroutine, Optional, TypeGuard
from cryptography.signature import Signature, Signed
from network_emulator import network
from protocol.credit.credit_types import ContractType, Transaction, FundWithdrawal, Receipt, Stake
from protocol.dialogue.base_dialogue import DialogueException
from protocol.dialogue.const import ControlPacket, DialogueEnum
from protocol.dialogue.dialogue_registry import register_init, register_response
from protocol.dialogue.packets import LatestChecksum
from protocol.dialogue.util.dialogue_util import DialogueUtil
from protocol.dialogue.util.util import RNGSeed, SelectedNode, filter_exceptions, gather_responses, select_witnesses, validate_selected_witnesses, validate_skips
from protocol.std_protocol.std_protocol import NodeData, StdProtocol, VerificationNodeData
from protocol.verification_net.verification_net_event import VNTEventFactory, VNTEventPacket
from settings import ACTIVE_RATIO, MIN_CONNECTIONS, STAKE_AMOUNT, VERIFICATION_CUTOFF, VERIFIER_REDUNDANCY

@register_init(DialogueEnum.HANDSHAKE)
async def handshake(du: DialogueUtil, protocol: StdProtocol):
    ...

@register_response(DialogueEnum.HANDSHAKE)
async def handshake_response(du: DialogueUtil, protocol: StdProtocol):
    du.acknowledge()

@register_init(DialogueEnum.CHECK_SAME_VNT)
async def check_same_vnt(du: DialogueUtil, protocol: StdProtocol, cutoff: Optional[float]=None) -> bool:
    """See if the checksums on the verification timeline match until the given cutoff"""
    
    await du.expect_acknowledgement()

    latest_before = protocol.verification_net_timeline.latest_before(cutoff)
    if latest_before is None:
        raise DialogueException('Empty VNT timeline')
    
    du.reply(cutoff)
    checksum = await du.expect(int)
    return checksum == latest_before.checksum

@register_response(DialogueEnum.CHECK_SAME_VNT)
async def check_same_vnt_response(du: DialogueUtil, protocol: StdProtocol):
    du.acknowledge()
    cutoff = await du.expect(float)
    
    latest_before = protocol.verification_net_timeline.latest_before(cutoff)
    if latest_before is None:
        raise DialogueException('Empty VNT')
    checksum = latest_before.checksum
    
    du.reply(checksum)
    return

@register_init(DialogueEnum.REQUEST_ADD_SELF)
async def request_add_self(du: DialogueUtil, protocol: StdProtocol):
    """Request that another node adds this node to it's node list"""
    
    await du.expect_acknowledgement()
    du.reply(NodeData(
        address=protocol.address,
        public_key=protocol.public_key,
    ))

@register_response(DialogueEnum.REQUEST_ADD_SELF)
async def request_add_self_response(du: DialogueUtil, protocol: StdProtocol):
    du.acknowledge()
    packet = await du.expect(NodeData)
    protocol.node_list.append(packet)

@register_init(DialogueEnum.REQUEST_NODE_LIST)
async def request_node_list(du: DialogueUtil, protocol: StdProtocol):
    """Requests a big enough random subset of the node list from another node to ensure enough redundant connections"""

    node_list = await du.expect(list[NodeData])
    results = await gather_responses(protocol, request_add_self, node_list, MIN_CONNECTIONS)
    protocol.node_list.extend(res.node for res in results)

@register_response(DialogueEnum.REQUEST_NODE_LIST)
async def request_node_list_response(du: DialogueUtil, protocol: StdProtocol):
    node_list = random.sample(protocol.node_list, int(2*MIN_CONNECTIONS/ACTIVE_RATIO))
    du.reply(node_list)

@register_init(DialogueEnum.GET_LATEST_HASH)
async def find_latest_checksum(du: DialogueUtil, protocol: StdProtocol) -> str | None:
    """Finds the latest checksum shared between this node and another node,
    which is exactly the point the two verification timelines start to differ"""

    same_vnt = await check_same_vnt(du, protocol)
    if same_vnt:
        latest = protocol.verification_net_timeline.latest()
        assert(latest is not None)
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
async def find_latest_checksum_response(du: DialogueUtil, protocol: StdProtocol) -> str | None:
    await check_same_vnt_response(du, protocol)
    await du.expect(ControlPacket.FAILURE)
    du.acknowledge()
    checksums = await du.expect(list[str])
    
    for cs in checksums:
        if cs in protocol.verification_net_timeline:
            matching_hash = cs
            du.reply(ControlPacket.SUCCESS)
            await du.expect_acknowledgement()
            du.reply(matching_hash)
            return matching_hash
        
    du.reply(ControlPacket.FAILURE)
    return None

@register_init(DialogueEnum.REQUEST_MISSING_EVENTS)
async def request_missing_events(du: DialogueUtil, protocol: StdProtocol, from_checksum: str):
    """Requests all the events which occurred after from_checksum"""

    await du.expect_acknowledgement()
    du.reply(LatestChecksum(checksum=from_checksum))
    return await du.expect(list[VNTEventPacket])

@register_response(DialogueEnum.REQUEST_MISSING_EVENTS)
async def request_missing_events_response(du: DialogueUtil, protocol: StdProtocol):
    du.acknowledge()
    from_checksum = await du.expect(LatestChecksum)
    from_checksum = from_checksum.checksum
    vnt = protocol.verification_net_timeline

    if from_checksum is not None:
        matched = vnt.from_checksum(from_checksum)
        if matched is None:
            raise DialogueException('Invalid dialogue state')
        events = list(event.to_packet() for event in vnt.iter_from(matched))
    else:
        events = list(event.to_packet() for event in vnt)
    du.reply(events)
    return events

@register_init(DialogueEnum.SEND_MISSING_EVENTS)
async def send_missing_events(du: DialogueUtil, protocol: StdProtocol, from_checksum: str):
    """Sends all the events which occurred after from_checksum"""

    vnt = protocol.verification_net_timeline
    matched = vnt.from_checksum(from_checksum)
    assert(matched)
    events = list(event.to_packet() for event in vnt.iter_from(matched))
    du.reply(events)
    return events

@register_response(DialogueEnum.SEND_MISSING_EVENTS)
async def send_missing_events_response(du: DialogueUtil, protocol: StdProtocol):
    du.acknowledge()
    events = await du.expect(list[VNTEventPacket])
    for event_packet in events:
        event = VNTEventFactory.from_packet(event_packet)
        protocol.verification_net_timeline.add(event)

@register_init(DialogueEnum.SYNC_VNT)
async def sync_vnt(du: DialogueUtil, protocol: StdProtocol):
    """Syncs this nodes vnt with another nodes vnt so that both nodes have all the events
    up to cutoff"""
    
    same_vnt = await check_same_vnt(du, protocol)
    if same_vnt:
        du.reply(ControlPacket.SUCCESS)
        return
    
    latest_checksum = await find_latest_checksum(du, protocol)
    if latest_checksum is None:
        raise DialogueException("Couldn't sync VNT")
    
    events = await request_missing_events(du, protocol, from_checksum=latest_checksum)
    await send_missing_events(du, protocol, from_checksum=latest_checksum)
    for event in events:
        protocol.verification_net_timeline.add(VNTEventFactory.from_packet(event))

    res = await check_same_vnt(du, protocol)
    if not res:
        raise DialogueException("Couldn't sync VNT")

@register_response(DialogueEnum.SYNC_VNT)
async def sync_vnt_response(du: DialogueUtil, protocol: StdProtocol):
    await check_same_vnt_response(du, protocol)
    res = du.expect(ControlPacket)
    if res == ControlPacket.SUCCESS:
        return
    await find_latest_checksum_response(du, protocol)
    await request_missing_events_response(du, protocol)
    await send_missing_events_response(du, protocol)
    await check_same_vnt(du, protocol)

@register_init(DialogueEnum.REQUEST_WITNESS_SIGNATURE)
async def request_signature(du: DialogueUtil, protocol: StdProtocol, contract: Signed[Transaction]) -> Signature:
    """Checks with a fund witness if there is enough credit remaining in the fund to cover the requested amount"""
    
    await du.expect_acknowledgement()
    du.reply(contract)
    return await du.expect(Signature)

@register_response(DialogueEnum.REQUEST_WITNESS_SIGNATURE)
async def request_signature_response(du: DialogueUtil, protocol: StdProtocol):
    du.acknowledge()
    signed_contract = await du.expect(Signed[Transaction])
    signed_contract.validate_signatures()

    contract = signed_contract.message
    seed = RNGSeed(contract.payer_public_key, contract.payee_public_key, contract.timestamp)
    validate_selected_witnesses(protocol, set(contract.witnesses), contract.timestamp, seed)
    
    relevant_funds = (fund for fund in contract.funds if fund.receipt_id.contract.payee_public_key == protocol.public_key)

    for fund in relevant_funds:
        receipt = fund.receipt_id
        if receipt not in protocol.receipt_book:
            raise DialogueException('No record of receipt')
    
        tracked_fund = protocol.receipt_book[receipt]
        if tracked_fund.available < fund.amount:
            raise DialogueException('Insufficient funds remaining')
        
    du.reply(protocol.sf.get_signature(contract))

@register_init(DialogueEnum.CONFIRM_TRANSACTION)
async def confirm_transaction(du: DialogueUtil, protocol: StdProtocol, receipt: Receipt) -> Signature:
    """Gets a signed confirmation that a witness has received the final transaction contract and updated the funds used for that transaction"""
    
    await du.expect_acknowledgement()
    du.reply(receipt)
    return await du.expect(Signature)

@register_response(DialogueEnum.CONFIRM_TRANSACTION)
async def confirm_transaction_response(du: DialogueUtil, protocol: StdProtocol):
    du.acknowledge()
    receipt = await du.expect(Receipt)

    if not receipt.signed_by(protocol.public_key):
        raise DialogueException('Missing own signature')
    receipt.validate_signatures()

    # TODO make it possible to claim the stake from other witnesses by providing signed contracts in excess of available funds

    relevant_funds = (fund for fund in receipt.contract.funds if fund.receipt_id in protocol.receipt_book)
    
    for fund in relevant_funds:
        protocol.receipt_book.update_credit(fund, receipt)

@register_init(DialogueEnum.REQUEST_HOLD_RECEIPT)
async def request_hold_receipt(du: DialogueUtil, protocol: StdProtocol, receipt: Signed[Receipt]):
    """Requests a node to hold the receipt for a transaction that just occurred"""
    
    await du.expect_acknowledgement()
    du.reply(receipt)
    await du.expect_acknowledgement()

@register_response(DialogueEnum.REQUEST_HOLD_RECEIPT)
async def request_hold_receipt_response(du: DialogueUtil, protocol: StdProtocol):
    du.acknowledge()
    signed_receipt = await du.expect(Signed[Receipt])

    if len(signed_receipt.signatures) < VERIFIER_REDUNDANCY:
        raise DialogueException('Not enough signatures')
    
    signed_receipt.validate_signatures()
    receipt = signed_receipt.message

    if not any(protocol.public_key == witness.public_key for witness in receipt.contract.witnesses):
        raise DialogueException('Not a witness for this transaction')
    
    receipt.validate_signatures()
    protocol.receipt_book.add(receipt)

    du.acknowledge()
    
@register_init(DialogueEnum.TRANSFER_CURRENCY)
async def transfer_currency(du: DialogueUtil, protocol: StdProtocol, amount: int, payee: NodeData):
    """Send currency to another wallet"""

    timestamp = time.time()
    cutoff = timestamp - VERIFICATION_CUTOFF
    seed = RNGSeed(protocol.public_key, payee.public_key, cutoff)

    # Helper function to sync missing events
    async def get_missing_events(witness: SelectedNode) -> list[VNTEventPacket]:
        wdu = witness.dialogue_util()
        latest_checksum = await find_latest_checksum(wdu, protocol)

        if latest_checksum is None:
            raise DialogueException("Couldn't sync VNT")
        
        latest_event = protocol.verification_net_timeline.from_checksum(latest_checksum)
        assert(latest_event is not None)
        
        if latest_event.timestamp > cutoff:
            return []

        missing = await request_missing_events(wdu, protocol, latest_checksum)
        return missing
    
    while True:
        # Reach out to witnesses
        witnesses, skipped = await select_witnesses(protocol, cutoff, seed)

        # Gather missing events
        results = await asyncio.gather(*(get_missing_events(witness) for witness in witnesses), return_exceptions=True)
        filtered_results = filter(filter_exceptions, results)
        missing_events = set(event for events in filtered_results for event in events)

        # If no missing events before the cutoff then we have the right witnesses
        if all(event.timestamp > cutoff for event in missing_events):
            # Make sure we're synced up with payee
            if await check_same_vnt(du, protocol):
                break
            await sync_vnt(du, protocol)

        for event_packet in missing_events:
            event = VNTEventFactory.from_packet(event_packet)
            protocol.verification_net_timeline.add(event)

    # Run stat tests on selected witnesses to make sure the selected witnesses are valid
    validate_skips(skipped)
    witness_nodes = tuple(witness.node for witness in witnesses)

    # Get collected sources of funds to be transferred
    wallet = protocol.wallet

    try:
        funds = wallet.find_funds(amount)
    except ValueError as e:
        raise DialogueException('Not enough funds to cover transfer')

    # Create and send contract
    countersigned_contract = Transaction(
        contract_type=ContractType.TRANSACTION,
        payer_address=protocol.address,
        payer_public_key=protocol.public_key,
        payee_address=payee.address,
        payee_public_key=payee.public_key,
        amount=amount,
        funds=tuple(funds),
        witnesses=witness_nodes,
        timestamp=timestamp,
        vnt_cutoff=cutoff
    )

    initial_contract = protocol.sign(countersigned_contract)

    await du.expect_acknowledgement()
    du.reply(initial_contract)
    
    countersigned_contract = await du.expect(Signed[Transaction]) # Signed by payer and payee but no witnesses yet
    
    # Get signatures from all witnesses
    async def get_signature(witness: VerificationNodeData, contract: Signed[Transaction]) -> Signature:
        nc = await network.connect(protocol.address, witness.address)
        wdu = DialogueUtil(nc)
        signature = await request_signature(wdu, protocol, contract)
        digest = hash(contract.message)
        signature.validate(digest)
        return signature
    
    tasks: list[set[asyncio.Task[Signature]]] = []
    for withdrawal in funds:
        task_set: set[asyncio.Task[Signature]] = set()
        for witness in withdrawal.receipt_id.contract.witnesses:
            task_set.add(asyncio.create_task(get_signature(witness, countersigned_contract)))
        tasks.append(task_set)

    signatures: list[Signature] = []
    for task_set in tasks:
        sig_count = 0
        done, _ = await asyncio.wait(task_set)

        for finished_task in done:
            try:
                signature = finished_task.result()
                signatures.append(signature)
            except (network.NetworkException, DialogueException) as e:
                ...

        if sig_count < VERIFIER_REDUNDANCY:
            raise DialogueException('Not enough signatures')

    # Validate witness signatures
    digest = hash(countersigned_contract.message)
    for sig in signatures:
        sig.validate(digest)

    fully_signed_contract = countersigned_contract.with_signatures(*signatures) # Signed by all witnesses as well
    receipt = Receipt(**vars(fully_signed_contract))
    du.reply(receipt) # Payment officially sent
    protocol.wallet.update_credit(receipt)
    await du.expect_acknowledgement()

@register_response(DialogueEnum.TRANSFER_CURRENCY)
async def transfer_currency_response(du: DialogueUtil, protocol: StdProtocol):
    du.acknowledge()
    
    # Initial contract
    signed_contract = await du.expect(Signed[Transaction]) # TODO test if this actually works with generics or not
    signed_contract.validate_signatures()
    contract = signed_contract.message
    
    # Check enough funds are included to cover payment
    if contract.amount != sum(fund.amount for fund in contract.funds):
        raise DialogueException('Invalid contract, not enough funds to cover payment')
    
    seed = RNGSeed(contract.payer_public_key, contract.payee_public_key, contract.timestamp)
    selected_witnesses = contract.witnesses
    validate_selected_witnesses(protocol, set(selected_witnesses), contract.timestamp, seed)
    
    # Validate signatures and selected witnesses for each fund
    for fund in contract.funds:
        fund.receipt_id.validate_signatures()
        fund_contract = fund.receipt_id.contract
        fund_seed = RNGSeed(fund_contract.payer_public_key, fund_contract.payee_public_key, fund_contract.timestamp)
        validate_selected_witnesses(protocol, set(fund_contract.witnesses), contract.timestamp, fund_seed)

    countersigned_contract = protocol.sign(contract)
    du.reply(countersigned_contract)
    receipt = await du.expect(Receipt) # Fully signed contract.

    # Verify that enough witnesses have signed and validate signatures
    if selected_witnesses != receipt.contract.witnesses:
        raise DialogueException('Invalid contract, invalid witnesses')
        
    for fund in receipt.contract.funds:
        signature_count = 0
        for witness in fund.receipt_id.contract.witnesses:
            if receipt.signed_by(witness.public_key):
                signature_count += 1

        if signature_count < VERIFIER_REDUNDANCY:
            raise DialogueException('Invalid contract, not enough signatures for fund')
        
    receipt.validate_signatures()

    du.acknowledge() # Payment is considered sent at this point.

    # Anything beyond this point can be done at a later time. The payment is already received we just need to notify the old / new witnesses.

    final_contract = receipt.contract

    async def connect_to_witness(witness: VerificationNodeData) -> DialogueUtil:
        nc = await network.connect(protocol.address, witness.address)
        return DialogueUtil(nc)

    async def get_witness_signature(connection: DialogueUtil):
        return await confirm_transaction(connection, protocol, receipt)
    
    connections = await asyncio.gather(*(connect_to_witness(witness) for witness in final_contract.witnesses), return_exceptions=True)
    connections = tuple(filter(filter_exceptions, connections))
    signatures = await asyncio.gather(*(get_witness_signature(wdu) for wdu in connections), return_exceptions=True)
    signatures = frozenset(filter(filter_exceptions, signatures))

    if len(signatures) < VERIFIER_REDUNDANCY:
        raise DialogueException('Not enough responses confirming transaction')
    
    signed_receipt = Signed(message=receipt, signatures=signatures)
    
    await asyncio.gather(*(request_hold_receipt(connection, protocol, signed_receipt) for connection in connections), return_exceptions=True)
    protocol.wallet.update_credit(receipt)

@register_init(DialogueEnum.CONFIRM_STAKE)
async def confirm_stake(du: DialogueUtil, protocol: StdProtocol, stake: Stake):
    """Get's a signature confirming that the stake has been reserved for the relevant funds"""

    await du.expect_acknowledgement()
    du.reply(stake)
    return await du.expect(Signature)
        

@register_response(DialogueEnum.CONFIRM_STAKE)
async def confirm_stake_response(du: DialogueUtil, protocol: StdProtocol):
    du.acknowledge()

@register_init(DialogueEnum.REQUEST_JOIN_VERIFICATION_NET)
async def request_join_verification_net(du: DialogueUtil, protocol: StdProtocol):
    timestamp = time.time()
    funds = protocol.wallet.find_funds(STAKE_AMOUNT)

    stake = Stake(
        contract_type=ContractType.STAKE,
        address=protocol.address,
        public_key=protocol.public_key,
        amount=STAKE_AMOUNT,
        funds=tuple(funds),
        timestamp=timestamp)
    
    async def get_signature(witness: VerificationNodeData) -> Signature:
        nc = await network.connect(protocol.address, witness.address)
        wdu = DialogueUtil(nc)
        signature = await confirm_stake(wdu, protocol, stake)
        digest = hash(stake)
        signature.validate(digest)
        return signature
    
    signature_cr: set[Coroutine[Any, Any, Signature]] = set()
    for fund in funds:
        for witness in fund.receipt_id.contract.witnesses:
            signature_cr.add(get_signature(witness))

    signatures = await asyncio.gather(*signature_cr, return_exceptions=True)
    signatures = frozenset(filter(filter_exceptions, signatures))

    signed_stake = Signed(message=stake, signatures=signatures)

@register_response(DialogueEnum.REQUEST_JOIN_VERIFICATION_NET)
async def request_join_verification_net_response(du: DialogueUtil, protocol: StdProtocol):
    du.acknowledge()

# TODO
# Bugfix infinite recursion in receipts. Funds don't need the whole receipt, no information about their own funds needed.
# Verification network join / leave / pause / unpause / entropy events.
# Change from eventual consistency with time limit to reach 100% consistency to zero consistency with
# stat checks for missing events. Instead of failing validation if selected witnesses don't match up
# exactly find out what events are missing or what extra events are included in the timeline and stat check for
# each missing event. Transaction include list of event uuids until cutoff (after which we assume consistency).
# Pay with contract you were a witness on, gas for witnesses.
# No verification for node 0 on transactions.
# Rollover.
# Get stake from fraudulent contract and contracts proving funds already ran out.