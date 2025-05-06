from asyncio import Task
import asyncio
from dataclasses import dataclass, field
import json
import random
import time
from typing import Any, Callable, Hashable, Self, cast
from cryptography.signature import Signed, SignatureFactory
from network_emulator import NetConnection, network as net
from protocol import AbstractProtocol
from protocol.credit.credit_types import Stake
from protocol.credit.receipt_book import ReceiptBook
from protocol.credit.wallet import Wallet
from protocol.dialogue.broadcast import Broadcast, BroadcastData
from protocol.dialogue import ControlPacket
from protocol.dialogue import dialogue_registry
from protocol.dialogue.const import DialogueEnum
from protocol.dialogue.util.dialogue_util import DialogueUtil
from protocol.verification_net.verification_net_timeline import VerificationNetTimeline
from settings import ACTIVE_RATIO, BROADCAST_AGGREGATION_DECAY, BROADCAST_SPREAD, MAX_BROADCAST_LIFETIME
import numpy as np

@dataclass(frozen=True)
class NodeData:
    '''The public node data for any node on the network'''
    address: int
    public_key: str

@dataclass(frozen=True)
class VerificationNodeData(NodeData):
    '''The public data for verification nodes on the network'''
    timestamp: float

@dataclass
class ActiveBroadcast:
    hash: int
    origin_time: float
    data: Any
    probabilities: list[float] = field(default_factory=list)
    visited: list[int] = field(default_factory=list)
    active_task: Task | None = None

@dataclass
class ProcessedBroadcast:
    hash: int
    origin_time: float
    data: Any
    visited: set[int] = field(default_factory=set)
    
class StdProtocol(AbstractProtocol):
    
    def __init__(self, node):
        super().__init__(node)
        self.node_list: list[NodeData] = []
        '''List of all nodes known to this node'''
        self.active_broadcasts: dict[int, ActiveBroadcast] = {}
        self.processed_broadcasts: dict[int, ProcessedBroadcast] = {}
        self.verification_net_timeline: VerificationNetTimeline = VerificationNetTimeline()
        '''Timeline of events (nodes joining/leaving etc) occurring on the verification subnetwork'''
        self.address = node.address
        self.wallet = Wallet(self.address)
        self.public_key: str
        self.private_key: str
        self.sf = SignatureFactory(
            public_key=self.public_key,
            private_key=self.private_key,
            address=self.address
        )
        self.stake: Stake | None = None
        self.receipt_book = ReceiptBook()
        '''Receipts held for other accounts'''

    @staticmethod
    def weight() -> float:
        return 1.0
    
    def sign[T: Hashable](self, message: T) -> Signed[T]:
        return self.sf.sign(message)

    async def _handle_broadcast(self, net_con: NetConnection, broadcast: Broadcast[Self, BroadcastData]):
        with net_con:
            net_con.write_out(ControlPacket.ACKNOWLEDGEMENT)
            data = await net_con.read_in()
            if data is None:
                return
            
            try:
                broadcast_data = broadcast.parse_data(data)
            except:
                return None
            
        lifetime = time.time() - broadcast_data.origin_time
        if lifetime > MAX_BROADCAST_LIFETIME:
            return
        
        if broadcast_data.hash not in self.processed_broadcasts:
            broadcast.execute(broadcast_data, self)
            self.processed_broadcasts[broadcast_data.hash] = ProcessedBroadcast(
                hash=broadcast_data.hash,
                origin_time=broadcast_data.origin_time,
                data=broadcast_data.data,
                visited=set(broadcast_data.visited)
            )
        else:
            self.processed_broadcasts[broadcast_data.hash].visited.update(broadcast_data.visited)

        if broadcast_data.hash in self.active_broadcasts:
            active_broadcast = self.active_broadcasts[broadcast_data.hash]
        else:
            active_broadcast = ActiveBroadcast(broadcast_data.hash, broadcast_data.data, broadcast_data.origin_time)
            self.active_broadcasts[broadcast_data.hash] = active_broadcast

        active_broadcast.probabilities.append(broadcast_data.rebroadcast_probability)
        if active_broadcast.active_task is not None:
            active_broadcast.active_task.cancel()

        active_broadcast.active_task = asyncio.create_task(self._aggregate_broadcasts(active_broadcast))
        active_broadcast.active_task.add_done_callback(lambda task: self.active_broadcasts.pop(active_broadcast.hash))

    async def write_out_broadcast(self, data: BroadcastData):
        visited = set(data.visited)
        nodes = [node for node in self.node_list if node.address not in visited]
        
        if len(nodes) <= BROADCAST_SPREAD:
            selected_nodes = nodes
        else:
            selected_nodes = random.sample(nodes, BROADCAST_SPREAD)

        for node_data in selected_nodes:
            if random.random() > data.rebroadcast_probability:
                continue
            
            nc = await net.connect(self._node.address, node_data.address)
            with nc:
                acknowledgement = await nc.read_in()
                if acknowledgement == ControlPacket.ACKNOWLEDGEMENT:
                    nc.write_out(json.dumps(data.dict()))

    async def _rebroadcast(self, active_broadcast: ActiveBroadcast):
        p = np.array(active_broadcast.probabilities)
        agg_p = 1 - (np.prod(1 - p))
        if l:=len(p) > 1:
            agg_p *= BROADCAST_AGGREGATION_DECAY**(l-1)
        
        rebroadcast_p = float(p**(1/(BROADCAST_SPREAD*ACTIVE_RATIO))) # The active ratio can actually be estimated in real time by including sampled data in the broadcast

        processed_broadcast = self.processed_broadcasts[active_broadcast.hash]
        
        try:
            data = BroadcastData(
                rebroadcast_probability=rebroadcast_p,
                origin_time=active_broadcast.origin_time,
                visited=list(processed_broadcast.visited),
                data=active_broadcast.data,
                hash=active_broadcast.hash
            )

            await self.write_out_broadcast(data)
        except Exception as e:
            ...

    async def _aggregate_broadcasts(self, active_broadcast: ActiveBroadcast):
        lifetime = time.time() - active_broadcast.origin_time
        await asyncio.sleep((1 + random.random()) * lifetime)
        self.add_task(self._rebroadcast(active_broadcast))

    def broadcast(self, data: BroadcastData):
        '''Fire and forget method for pushing a new broadcast'''
        self.add_task(self.write_out_broadcast(data))

    def get_response(self, dialogue_key: DialogueEnum):
        """Get's the response for an incoming dialogue from the registry.
        Overwrite to add custom behavior for certain dialogue responses"""
        return dialogue_registry.get_response(dialogue_key)

    async def _monitor_net_connection(self, net_con: NetConnection):
        with net_con:
            while net_con.is_open:
                dialogue_key = cast(DialogueEnum, await net_con.read_in())
                assert(dialogue_key is not None)
                dialogue = self.get_response(dialogue_key)
                if isinstance(dialogue, Broadcast):
                    await self._handle_broadcast(net_con, dialogue)
                elif isinstance(dialogue, Callable):
                    du = DialogueUtil(net_con)
                    await dialogue(du, self, net_con=net_con)

    def accept_net_connection(self, net_con: NetConnection):
        '''Accepts an incoming net connection'''
        self.add_task(self._monitor_net_connection(net_con))