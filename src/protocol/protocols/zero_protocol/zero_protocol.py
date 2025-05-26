from typing import Callable, Hashable, cast

from protocol.dialogue.zero_dialogues import DIALOGUES, RESPONSES
import timeline
from crypto.signature import SignatureFactory, Signed
from crypto.util import PrivateKey, PublicKey
from network_emulator import network
from network_emulator.net_connection import NetConnection
from protocol.dialogue.const import DialogueEnum
from protocol.dialogue.util.dialogue_util import DialogueUtil
from protocol.protocols.abstract_protocol import AbstractProtocol
from protocol.protocols.common_types import NodeData, VerificationNodeData
from protocol.verification_net.verification_net_timeline import VerificationNetTimeline
from protocol.verification_net.vnt_types import VerificationNetEvent
from settings import NODE_0_PRIVATE_KEY, NODE_0_PUBLIC_KEY


class ZeroProtocol(AbstractProtocol):

    def __init__(self, node):
        super().__init__(node)
        self.verification_net_timeline: VerificationNetTimeline = (
            VerificationNetTimeline()
        )
        """Timeline of events (nodes joining/leaving etc) occurring on the verification subnetwork"""
        self._public_key_obj = PublicKey.from_pem(NODE_0_PUBLIC_KEY)
        self._private_key_obj = PrivateKey.from_pem(NODE_0_PRIVATE_KEY)
        self.public_key = self._public_key_obj.as_str()
        self.private_key = self._private_key_obj.as_str()
        self.sf = SignatureFactory(
            public_key=self._public_key_obj,
            private_key=self._private_key_obj,
            address=self.address,
        )
        self.verification_net_timeline.subscribe(
            lambda event: self.on_event_added(event)
        )

    @staticmethod
    def weight() -> float:
        return 0

    @property
    def node_data(self):
        return NodeData(self.address, self.public_key)

    @classmethod
    def dialogues(cls):
        return DIALOGUES

    @classmethod
    def responses(cls):
        return RESPONSES

    def sign[T: Hashable](self, message: T) -> Signed[T]:
        return self.sf.sign(message)

    def verification_node_data(self) -> VerificationNodeData:
        return VerificationNodeData(self.address, self.public_key, 0)

    async def _monitor_net_connection(self, net_con: NetConnection):
        with net_con:
            while net_con.is_open:
                dialogue_key = cast(DialogueEnum, await net_con.read_in())
                assert dialogue_key is not None
                dialogue = self.get_response(dialogue_key)
                if isinstance(dialogue, Callable):
                    du = DialogueUtil(net_con)
                    await dialogue(du, self, net_con=net_con)

    def accept_net_connection(self, net_con: NetConnection):
        """Accepts an incoming net connection"""
        self.add_task(self._monitor_net_connection(net_con))

    def schedule_event(self, time: float, callback: Callable):
        timeline.schedule_event(time, callback)

    def on_event_added(self, event: VerificationNetEvent): ...

    async def transfer_credit_to(self, amount: int, payee: NodeData):
        await self.run_dialogue(payee.address, DialogueEnum.TRANSFER_CREDIT, amount, payee)
