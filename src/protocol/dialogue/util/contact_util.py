import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Concatenate, Coroutine, Iterable, Optional, TypeGuard

from network_emulator import network
from network_emulator.network_exceptions import NetworkException
from protocol.dialogue.dialogue_types import DialogueException
from protocol.dialogue.util.dialogue_util import DialogueUtil
from protocol.protocols.common_types import NodeData, VerificationNodeData

if TYPE_CHECKING:
    from protocol.verification_net.verification_net_timeline import VerificationNetTimeline
    from protocol.protocols.abstract_protocol import AbstractProtocol

@dataclass
class Response[R]:
    node: NodeData
    result: R

async def gather_responses[T: 'AbstractProtocol', R](protocol: T,
                              dialogue: Callable[Concatenate[DialogueUtil, T, ...], Coroutine[None, None, R]],
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
            
            if tasks:
                await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)

    except (StopIteration, MaxFailuresReached) as e:
        for task in tasks:
            task.cancel()
        raise NetworkException(f"{n_successes} responses required but only received {successes} ({failures} unresponsive)")
    
    return results

def filter_exceptions[T](val: T | BaseException) -> TypeGuard[T]:
        return not isinstance(val, BaseException)

async def contact_all_verification_nodes[T: 'AbstractProtocol', **P](protocol: T,
                                                                   vnt: 'VerificationNetTimeline',
                                                                   dialogue: Callable[Concatenate[DialogueUtil, T, P], Any],
                                                                   *args: P.args,
                                                                   **kwargs: P.kwargs):
    
    verifiers = vnt.to_list()

    async def contact(node: VerificationNodeData):
        vnc = await network.connect(protocol.address, node.address)
        with vnc:
            vdu = DialogueUtil(vnc)
            await dialogue(vdu, protocol, *args, **kwargs)

    dialogue_tasks: set[asyncio.Task] = set(asyncio.create_task(contact(node)) for node in verifiers)

    if dialogue_tasks:
        await asyncio.wait(dialogue_tasks)
