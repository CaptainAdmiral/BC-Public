import asyncio
from dataclasses import dataclass
import numpy as np
from typing import Any, Callable, Concatenate, Coroutine, Generator, Iterable, Optional

from network_emulator import network
from network_emulator.network import NetworkException
from protocol.dialogue.dialogue_graph import DialogueException
from protocol.dialogue.util.dialogue_util import DialogueUtil
from protocol.dialogue.util.stat import check_consecutive_skips, check_total_skipped
from protocol.std_protocol.std_protocol import NodeData, StdProtocol, VerificationNodeData
from protocol.verification_net.verification_net_timeline import VerificationNetTimeline
import protocol.dialogue.dialogues as dialogues

from settings import TRANSACTION_WITNESSES

@dataclass
class Response[R]:
    node: NodeData
    result: R

@dataclass
class SelectedNode:
    node: NodeData
    skipped: bool
    net_con: network.NetConnection | None

def witness_selection_iter(vnt: VerificationNetTimeline, cutoff: float) -> Generator[VerificationNodeData, Any, None]:
    verification_nodes = vnt.to_list(cutoff)
    seed = vnt.get_random_seed(cutoff)
    rand = np.random.default_rng(seed) # TODO substitute a random generator that's been checked for bias
    
    while True:
        if verification_nodes:
            yield verification_nodes.pop(rand.integers(0, len(verification_nodes)))
        else:
            break

def validate_selected_witnesses(protocol: StdProtocol, selected_nodes: list[SelectedNode], cutoff: float):
    """Checks whether the selected nodes were the expected selected nodes and raises an error if they weren't or
    if the selected nodes were statistically implausible"""

    ws_iter = witness_selection_iter(protocol.verification_net_timeline, cutoff)

    # Check that the nodes we expect to be chosen are actually the nodes chosen
    
    skip_list: list[bool] = []
    for expected_node, selected in zip(ws_iter, selected_nodes):
        selected_node = selected.node
        if selected_node != expected_node:
            raise DialogueException('Unexpected node selected as witness')
        skip_list.append(selected.skipped)

    # Verify the sequence of skipped nodes reported is statistically plausible
        
    skip_array = np.array(skip_list)
    check_total_skipped(skip_array)
    check_consecutive_skips(skip_array)

async def select_witnesses(protocol: StdProtocol, cutoff: float) -> list[SelectedNode]:
    """Randomly selects nodes from the verification network in accordance with the random seed at time 'cutoff'"""

    successes = 0
    unresolved = 0
    tasks: set[asyncio.Task] = set()
    selected_nodes: list[SelectedNode] = []
        
    async def check_connection(node_data: VerificationNodeData):
        nonlocal successes, unresolved

        net_con = await protocol._request_net_connection(network.get_node(node.address))
        du = DialogueUtil(net_con)
        skip = False
        try:
            net_con.open()
            await dialogues.handshake(du, protocol)
            successes += 1
        except NetworkException as e:
            return
        except DialogueException as e:
            net_con.close()
            return
        finally:
            selected_nodes.append(SelectedNode(node=node_data, skipped=skip, net_con=net_con))
            unresolved -= 1

    ws_iter = witness_selection_iter(protocol.verification_net_timeline, cutoff)

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
        raise e
    
    return selected_nodes
            
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

        net_con = await protocol._request_net_connection(network.get_node(node.address))
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