from typing import Any, cast
import json
from pydantic import TypeAdapter
from network_emulator import NetConnection
import protocol.dialogue.base_dialogue as bd
from protocol.dialogue.const import ControlPacket
from protocol.dialogue.const import DialogueEnum

class DialogueUtil:
    def __init__(self, net_connection: NetConnection):
        self.net_connection = net_connection

    def reply(self, reply: Any) -> None:
        if reply is None:
            raise bd.DialogueException('Empty Reply')
        
        rep = TypeAdapter(Any).dump_json(reply).decode()
        self.net_connection.write_out(rep)

    def init(self, dialogue: DialogueEnum):
        self.reply(dialogue)

    async def expect[D](self, expect: D | type[D]) -> D:
        # TODO process in all raw data types including from list
        processed_data = None

        data_str = await self.net_connection.read_in()
        if data_str is None:
            raise bd.DialogueException(f"Empty response!")
        if data_str == ControlPacket.REFUSAL:
            raise bd.DialogueException('Request refused')
        elif data_str == ControlPacket.ERROR:
            raise bd.DialogueException('Dialogue partner errored')
        
        if isinstance(expect, type):
            adapter = TypeAdapter(expect)
            processed_data = adapter.validate_json(data_str)
        else:
            processed_data = json.loads(data_str)
            if expect != processed_data:
                raise bd.DialogueException(f"Expected {expect} but got {data_str}")
        
        return cast(D, processed_data)
    
    def acknowledge(self):
        '''Sends an acknowledgement packet'''
        return self.reply(ControlPacket.ACKNOWLEDGEMENT)
    
    def expect_acknowledgement(self):
        '''Expects an acknowledgement packet'''
        return self.expect(ControlPacket.ACKNOWLEDGEMENT)
