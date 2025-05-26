import asyncio
from dataclasses import dataclass
import numpy as np
from typing import TYPE_CHECKING, AbstractSet, Any, Generator, Iterable, Optional

from crypto.util import RandomGen
from network_emulator import network
from network_emulator.net_connection import NetConnection
from network_emulator.network_exceptions import NetworkException
from protocol.dialogue.const import DialogueEnum
from protocol.dialogue.dialogue_types import DialogueException
from protocol.dialogue.util.dialogue_util import DialogueUtil
from protocol.dialogue.util.rng_seed import RNGSeed
from protocol.dialogue.util.stat import check_consecutive_skips, check_missing_events, check_total_skipped
from protocol.protocols.common_types import VerificationNodeData

from settings import NODE_0_PUBLIC_KEY, TRANSACTION_WITNESSES

if TYPE_CHECKING:
    from protocol.verification_net.verification_net_timeline import VerificationNetTimeline
    from protocol.protocols.abstract_protocol import AbstractProtocol
    from protocol.verification_net.vnt_types import VerificationNetEvent

@dataclass
class SelectedNode:
    node: VerificationNodeData
    net_con: NetConnection

    def dialogue_util(self):
        return DialogueUtil(self.net_con)

@dataclass
class SelectedWitnesses:
    witnesses: list[SelectedNode]

    def close_all_connections(self):
        for witness in self.witnesses:
            witness.net_con.close()

def witness_selection_iter(vnt: 'VerificationNetTimeline',
                           cutoff: float,
                           rng_seed: RNGSeed,
                           missing_event_ids: Optional[set[str]]=None) -> Generator[VerificationNodeData, Any, None]:
    verification_nodes = vnt.to_list(cutoff=cutoff, excluded_event_ids=missing_event_ids)
    rng = RandomGen(rng_seed)
    
    while True:
        if verification_nodes:
            node = verification_nodes.pop(rng.next(len(verification_nodes)))
            if node.public_key == rng_seed.payee_public_key:
                continue
            if node.public_key == rng_seed.payer_public_key:
                continue
            if node.public_key == NODE_0_PUBLIC_KEY:
                continue
            yield node
        else:
            break

def validate_skips(skip_list: Iterable[bool]):
    """Checks if a sequence of skipped nodes during witness selection is statistically valid"""

    skip_array = np.array(skip_list)
    check_total_skipped(skip_array)
    check_consecutive_skips(skip_array)

def validate_selected_witnesses(vnt: 'VerificationNetTimeline',
                                selected_nodes: AbstractSet[VerificationNodeData],
                                cutoff: float,
                                seed: RNGSeed,
                                missing_event_ids: Optional[set[str]]=None):
    """Checks whether the selected nodes were the expected selected nodes and raises an error if they weren't or
    if the selected nodes were statistically implausible"""

    ws_iter = witness_selection_iter(vnt, cutoff, seed, missing_event_ids) # TODO handle iterator exhausted
    skip_iter = (node not in selected_nodes for node in ws_iter)

    # Verify the sequence of skipped nodes reported is statistically plausible
    validate_skips(skip_iter)

def validate_missing_events(missing_events: 'Iterable[VerificationNetEvent]', timestamp: float):
    """Checks whether the events unknown to all parties at the time of transaction are statistically plausible"""
    check_missing_events(missing_events, timestamp)

async def select_witnesses(protocol: 'AbstractProtocol', vnt: 'VerificationNetTimeline', cutoff: float, seed: RNGSeed) -> tuple[SelectedWitnesses, list[bool]]:
    """Selects and reaches out to nodes from the verification network in accordance with the random seed at time 'cutoff'.
    Skips unresponsive nodes. A list of boolean values representing whether nodes are skipped is returned as well
    to check selection is statistically valid.

    Args:
        seed: Transaction data used to seed the rng for witness selection
    
    Returns:
        tuple[SelectedWitnesses,list[bool]]: Selected nodes object, skip_list"""

    successes = 0
    unresolved = 0
    tasks: set[asyncio.Task] = set()
    selected_nodes: list[SelectedNode] = []
    skip_list = []
    open_connections: set[NetConnection] = set()
        
    async def check_connection(node_data: VerificationNodeData):
        nonlocal successes, unresolved

        net_con = await network.connect(protocol.address, node_data.address) 
        skipped = True
        try:
            open_connections.add(net_con)
            net_con.open()
            du = DialogueUtil(net_con)
            await protocol.dialogues()[DialogueEnum.HANDSHAKE](du, protocol)
            successes += 1
            skipped = False
        except (NetworkException, DialogueException) as e:
            net_con.close()
            open_connections.remove(net_con)
            return
        finally:
            selected_nodes.append(SelectedNode(node=node_data, net_con=net_con))
            unresolved -= 1
            skip_list.append(skipped)

    ws_iter = witness_selection_iter(vnt, cutoff, seed)

    try:
        while successes < TRANSACTION_WITNESSES:
            for i in range(TRANSACTION_WITNESSES - successes - unresolved):
                node = next(ws_iter)
                task = asyncio.create_task(check_connection(node))
                unresolved += 1
                tasks.add(task)
                task.add_done_callback(tasks.discard)
            if tasks:
                await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
    except StopIteration as e:
        for task in tasks:
            task.cancel()
        for nc in open_connections:
            nc.close()
        raise e
    
    return SelectedWitnesses(selected_nodes), skip_list