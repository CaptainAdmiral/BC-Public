from types import UnionType
from typing import Any, cast
import json
from pydantic import BaseModel
from network_emulator import NetConnection
import protocol.dialogue.base_dialogue as bd
from protocol.dialogue.const import ControlPacket
from protocol.dialogue.const import DialogueEnum

type Primitive = str | bool | int | float | ControlPacket | None
type DataType = Primitive | BaseModel

class DialogueUtil:
    def __init__(self, net_connection: NetConnection):
        self.net_connection = net_connection

    def reply(self, reply: Any) -> None:
        if reply is None:
            raise bd.DialogueException('Empty Reply')
        
        rep = None
        if isinstance(reply, BaseModel):
            rep = reply.model_dump_json()
        
        self.net_connection.write_out(rep)

    def init(self, dialogue: DialogueEnum):
        self.reply(dialogue)

    async def expect[D: DataType](self, expect: D | type[D] | UnionType) -> D:
        # TODO process in all raw data types including from list
        processed_data = None

        data_str = await self.net_connection.read_in()
        if data_str == ControlPacket.REFUSAL:
            raise bd.DialogueException('Request refused')
        
        data_obj = None if data_str is None else json.loads(data_str)
        if data_obj is None:
            raise bd.DialogueException(f"Empty response!")

        if isinstance(expect, str):
            processed_data = data_str
            if expect == ControlPacket.REFUSAL:
                raise bd.DialogueException('Dialogue refused')
            elif expect == ControlPacket.ERROR:
                raise bd.DialogueException('Dialogue partner errored')
            if expect != data_str:
                raise bd.DialogueException(f"Expected {expect} but got {data_str}")
        
        elif isinstance(expect, type):
            if issubclass(expect, BaseModel):
                processed_data = expect(**cast(dict, data_obj))
            elif isinstance(data_obj, expect):
                processed_data = data_obj
            else:
                raise bd.DialogueException(f"Expected {expect} but got {data_str}")
        else:
            raise TypeError('Unhandled type in expect')
        
        return cast(D, processed_data)
    
    def acknowledge(self):
        '''Sends an acknowledgement packet'''
        return self.reply(ControlPacket.ACKNOWLEDGEMENT)
    
    def expect_acknowledgement(self):
        '''Expects an acknowledgement packet'''
        return self.expect(ControlPacket.ACKNOWLEDGEMENT)
