from typing import TYPE_CHECKING, Callable, Hashable, cast

import network_emulator.network as net
import timeline
from crypto.signature import SignatureFactory, Signed
from crypto.util import generate_keypair
from protocol import AbstractProtocol
from protocol.credit.receipt_book import ReceiptBook
from protocol.credit.wallet import Wallet
from protocol.dialogue.const import DialogueEnum
from protocol.dialogue.dialogues import DIALOGUES, RESPONSES
from protocol.dialogue.util.dialogue_util import DialogueUtil
from protocol.protocols.common_types import NodeData, VerificationNodeData
from protocol.verification_net.verification_net_timeline import VerificationNetTimeline
from protocol.verification_net.vnt_types import (
    LeaveEvent,
    VerificationNetEvent,
    VerificationNetEventEnum,
)
from settings import TIME_TO_CONSISTENCY

if TYPE_CHECKING:
    from protocol.credit.credit_types import Stake


class StdProtocol(AbstractProtocol):

    def __init__(self, node):
        super().__init__(node)
        self.node_list: list[NodeData] = []
        """List of all nodes known to this node"""
        self.verification_net_timeline: VerificationNetTimeline = (
            VerificationNetTimeline()
        )

        """Timeline of events (nodes joining/leaving etc) occurring on the verification subnetwork"""
        self.wallet = Wallet(self.address)
        self._public_key_obj, self._private_key_obj = generate_keypair()
        self.public_key = self._public_key_obj.as_str()
        self.private_key = self._private_key_obj.as_str()
        self.sf = SignatureFactory(
            public_key=self._public_key_obj,
            private_key=self._private_key_obj,
            address=self.address,
        )
        self.receipt_book = ReceiptBook()
        """Receipts held for other accounts"""
        self.stake: "Stake | None" = None

        self.verification_net_timeline.subscribe(
            lambda event: self.on_event_added(event)
        )

    @staticmethod
    def weight() -> float:
        return 1.0

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
        if self.stake is None:
            raise RuntimeError(
                "Requesting verification node data but protocol does not have a stake for the verification net"
            )
        return VerificationNodeData(self.address, self.public_key, self.stake.timestamp)

    def schedule_event(self, time: float, callback: Callable):
        timeline.schedule_event(time, callback)

    def on_event_added(self, event: VerificationNetEvent):
        if event.event_type() == VerificationNetEventEnum.NODE_LEAVE:
            event = cast(LeaveEvent, event)
            if self.public_key in (
                witness.public_key for witness in event.data.stake_witnesses
            ):

                def schedule_stake_release():
                    for fund_id in event.data.fund_ids:
                        if fund_id in self.receipt_book:
                            self.receipt_book[fund_id].release_credit(
                                event.data.stake_id
                            )

                self.schedule_event(
                    event.timestamp + TIME_TO_CONSISTENCY, schedule_stake_release
                )

    async def transfer_credit_to(self, amount: int, payee: NodeData):
        nc = await net.connect(self.address, payee.address)
        du = DialogueUtil(nc)
        await self.dialogues()[DialogueEnum.TRANSFER_CREDIT](du, self, amount, payee)

    async def request_missing_events_from(self, node: NodeData):
        nc = await net.connect(self.address, node.address)
        du = DialogueUtil(nc)
        await self.dialogues()[DialogueEnum.TRANSFER_CREDIT](du, self)
