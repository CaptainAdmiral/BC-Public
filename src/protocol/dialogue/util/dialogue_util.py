import json
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, cast, get_origin

from protocol.dialogue.const import ControlPacket, DialogueEnum
from protocol.dialogue.dialogue_types import DialogueException
from util.type_adapters import get_type_adapter

if TYPE_CHECKING:
    from network_emulator.net_connection import NetConnection


class DialogueUtil:
    class ComType(Enum):
        OUT = auto()
        IN = auto()

    def __init__(self, net_connection: 'NetConnection'):
        self.net_connection = net_connection
        self._last_com_type: DialogueUtil.ComType | None = None
        self._errored = False

        if not net_connection.is_open:
            raise ValueError(
                "DialogueUtil requires an open net connection, received a closed net connection"
            )

    def reply(self, reply: Any) -> None:
        if self._last_com_type == self.ComType.OUT:
            raise DialogueException("Sending two dialogue packets in a row not allowed")

        if not self.net_connection.is_open:
            raise DialogueException(
                f"Tried to write to a closed net connection: {reply}"
            )

        if reply is None:
            raise DialogueException("Empty Reply")

        rep = get_type_adapter(Any).dump_json(reply).decode()
        self._last_com_type = self.ComType.OUT
        self.net_connection.write_out(rep)

    def init(self, dialogue: DialogueEnum):
        self.reply(dialogue)

    async def expect[D](self, expect: D | type[D]) -> D:
        # TODO process in all raw data types including from list
        if self._last_com_type == self.ComType.IN:
            raise DialogueException(
                "Receiving two dialogue packets in a row not allowed"
            )
        self._last_com_type = self.ComType.IN

        processed_data = None

        data_str = await self.net_connection.read_in()
        if data_str is None:
            raise DialogueException(f"Empty response!")
        if data_str == '"' + ControlPacket.REFUSAL + '"':
            raise DialogueException("Request refused")
        elif data_str == '"' + ControlPacket.ERROR + '"':
            raise DialogueException("Dialogue partner errored")

        if isinstance(expect, type) or get_origin(expect) is not None:
            adapter = get_type_adapter(expect)
            try:
                processed_data = adapter.validate_json(data_str)
            except Exception as e:
                raise DialogueException(f"Could not parse json: {data_str}")
        else:
            try:
                processed_data = json.loads(data_str)
            except Exception as e:
                raise DialogueException(f"Could not parse json: {data_str}")

            if expect != processed_data:
                raise DialogueException(f"Expected {expect} but got {data_str}")

        return cast(D, processed_data)

    def acknowledge(self):
        """Sends an acknowledgement packet"""
        return self.reply(ControlPacket.ACKNOWLEDGEMENT)

    def expect_acknowledgement(self):
        """Expects an acknowledgement packet"""
        return self.expect(ControlPacket.ACKNOWLEDGEMENT)

    def error(self):
        if not self._errored:
            self._errored = True
            try:
                if self.net_connection.is_open:
                    self.reply(ControlPacket.ERROR)
            except Exception:
                ...

            self.net_connection.close()
