import asyncio
from dataclasses import dataclass
import numpy as np
from typing import AbstractSet, Any, Callable, Concatenate, Coroutine, Generator, Iterable, Optional, TypeGuard

from network_emulator import network
from network_emulator.network import NetworkException
from protocol.dialogue.dialogue_graph import DialogueException
from protocol.dialogue.util.dialogue_util import DialogueUtil
from protocol.dialogue.util.stat import check_consecutive_skips, check_total_skipped
from protocol.std_protocol.std_protocol import NodeData, StdProtocol, VerificationNodeData
from protocol.verification_net.verification_net_timeline import VerificationNetTimeline
import protocol.dialogue.dialogues as dialogues

from settings import TRANSACTION_WITNESSES

@dataclass(frozen=True)
class RNGSeed:
    """Part of the seed for witness selection RNG. The actual entropy comes from the latest hash of the network
    but to prevent the same nodes from being overloaded by every transaction on that hash we determine the seed
    based on a few extra values as well."""

    payer_public_key: str
    payee_public_key: str
    timestamp: float

    def __hash__(self):
        # Values are strongly quantized here first to prevent RNG manipulation
        # TODO Strongly quantize values first to reduce RNG manipulation
        return hash(self)

@dataclass
class Response[R]:
    node: NodeData
    result: R

@dataclass
class SelectedNode:
    node: VerificationNodeData
    net_con: network.NetConnection

    def dialogue_util(self):
        return DialogueUtil(self.net_con)

def witness_selection_iter(vnt: VerificationNetTimeline, cutoff: float, rng_seed: RNGSeed) -> Generator[VerificationNodeData, Any, None]:
    verification_nodes = vnt.to_list(cutoff)
    latest_checksum = vnt.get_latest_checksum(cutoff)
    seed = hash((latest_checksum, hash(rng_seed)))
    rand = np.random.default_rng(seed) # TODO substitute a random generator that's been checked for bias
    
    while True:
        if verification_nodes:
            yield verification_nodes.pop(rand.integers(0, len(verification_nodes)))
        else:
            break

def validate_skips(skip_list: Iterable[bool]):
    """Checks if a sequence of skipped nodes during witness selection is statistically valid"""

    skip_array = np.array(skip_list)
    check_total_skipped(skip_array)
    check_consecutive_skips(skip_array)

def validate_selected_witnesses(protocol: StdProtocol, selected_nodes: AbstractSet[VerificationNodeData], cutoff: float, seed: RNGSeed):
    """Checks whether the selected nodes were the expected selected nodes and raises an error if they weren't or
    if the selected nodes were statistically implausible"""

    ws_iter = witness_selection_iter(protocol.verification_net_timeline, cutoff, seed) # TODO handle iterator exhausted
    skip_iter = (node not in selected_nodes for node in ws_iter)

    # Verify the sequence of skipped nodes reported is statistically plausible
    validate_skips(skip_iter)

async def select_witnesses(protocol: StdProtocol, cutoff: float, seed: RNGSeed) -> tuple[list[SelectedNode], list[bool]]:
    """Selects and reaches out to nodes from the verification network in accordance with the random seed at time 'cutoff'.
    Skips unresponsive nodes. A list of boolean values representing whether nodes are skipped is returned as well
    to check selection is statistically valid.

    Args:
        seed: Transaction data used to seed the rng for witness selection
    
    Returns:
        tuple[list[SelectedNode],list[bool]]: Selected nodes, skip_list"""

    successes = 0
    unresolved = 0
    tasks: set[asyncio.Task] = set()
    selected_nodes: list[SelectedNode] = []
    skip_list = []
        
    async def check_connection(node_data: VerificationNodeData):
        nonlocal successes, unresolved

        net_con = await protocol._request_net_connection(node.address)
        du = DialogueUtil(net_con)
        skipped = True
        try:
            net_con.open()
            await dialogues.handshake(du, protocol)
            successes += 1
            skipped = False
        except NetworkException as e:
            return
        except DialogueException as e:
            net_con.close()
            return
        finally:
            selected_nodes.append(SelectedNode(node=node_data, net_con=net_con))
            unresolved -= 1
            skip_list.append(skipped)

    ws_iter = witness_selection_iter(protocol.verification_net_timeline, cutoff, seed)

    try:
        while successes < TRANSACTION_WITNESSES:
            for i in range(TRANSACTION_WITNESSES - successes - unresolved):
                node = next(ws_iter)
                task = asyncio.create_task(check_connection(node))
                unresolved += 1
                tasks.add(task)
                task.add_done_callback(tasks.discard)
            await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
    except StopIteration as e:
        for task in tasks:
            task.cancel()
        raise e
    
    return selected_nodes, skip_list
            
async def gather_responses[R](protocol: StdProtocol,
                              dialogue: Callable[Concatenate[DialogueUtil, StdProtocol, ...], Coroutine[None, None, R]],
                              node_list: Iterable[NodeData],
                              n_successes: int = 1,
                              *args,
                              max_failures: Optional[int] = None,
                              **kwargs) -> list[Response[R]]:
    '''Iterates through the list of nodes attempting to start a dialogue until the dialogue has been completed successfully with n nodes'''

    successes = 0
    failures = 0
    unresolved = 0

    tasks: set[asyncio.Task] = set()
    results: list[Response[R]] = []

    node_iter = iter(node_list)

    async def process_dialogue(node: NodeData, *args, **kwargs):
        nonlocal successes, failures, unresolved

        net_con = await protocol._request_net_connection(node.address)
        result = None
        try:
            with net_con:
                du = DialogueUtil(net_con)
                result = await dialogue(du, protocol)
        except (NetworkException, DialogueException) as e:
            ...

        if result:
            results.append(Response(node, result))
            successes += 1
        else:
            failures += 1

        unresolved -= 1

    def try_next_node():
        nonlocal unresolved

        node = next(node_iter)
        task = asyncio.create_task(process_dialogue(node, *args, **kwargs))
        unresolved += 1
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    class MaxFailuresReached(Exception):
        ...

    try:
        while successes < n_successes:
            if max_failures and failures >= max_failures:
                raise MaxFailuresReached()

            remaining = n_successes - successes
            for i in range(remaining - unresolved):
                try_next_node()
            
            await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)

    except (StopIteration, MaxFailuresReached) as e:
        for task in tasks:
            task.cancel()
        raise NetworkException(f"{n_successes} responses required but only received {successes} ({failures} unresponsive)")
    
    return results

def filter_exceptions[T](val: T | BaseException) -> TypeGuard[T]:
        return not isinstance(val, BaseException)