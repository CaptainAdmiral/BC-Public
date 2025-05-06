from network_emulator.net_connection import*
from protocol import*
from protocol import protocol_factory
from async_manager import run
from protocol.dialogue.dialogue_registry import validate_registries

def register_protocols():
    protocol_factory.register_protocols(StdProtocol)

def initialize_network():
    pass

if __name__ == "main":
    register_protocols()
    validate_registries()
    initialize_network()
    asyncio.run(run())