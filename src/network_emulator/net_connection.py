import asyncio
import network
from async_manager import add_async_task
from node import Node
from enum import StrEnum

class NetConnection():
    """Net connection emulator class for sending packets between two nodes on the network.
    
    NetConnections are implemented as pairs of instances where each NetConnection writes it's data out to it's inverse and vica versa.
    """

    _network_traffic_tasks: set[asyncio.Task] = set()

    class Packets(StrEnum):
        CLOSE = 'close'

    class NetConnectionClosedException(network.NetworkException):
        """Raised when write operations are attempted on a closed NetConnection """        
        pass

    class NoInverseException(network.NetworkException):
        """Raised when an operation is attempted on a NetConnection that does not have an inverse """ 

        def __init__(self, message=''):
            super().__init__("NetConnection does not have an inverse! Please make sure you assign the inverse to another node first using get_inverse()"+'\n'+message)

    def __init__(self, node: Node, other_node: Node, *, inverse=None):
        self.is_open = False
        self.in_waiting = False
        self._inverse: NetConnection | None = inverse

        if not self._inverse:
            self._inverse = NetConnection(self._other_node, self._node, inverse=self) 

        self._node = node
        self._other_node = other_node
        self._read_buffer = []

        self._read_event = asyncio.Event()
        self._outgoing_packets = set()

    def __enter__(self):
        if not self.is_open:
            self.open()

    def __exit__(self, type, value, traceback):
        self.close()

    def get_inverse(self) -> 'NetConnection':
        """Returns the inverse net connection to this net connection

        Raises:
            NoInverseException: if the inverse for this net connection does not exist

        Returns:
            SelfType: inverse NetConnection
        """        
        if not self._inverse:
            raise self.NoInverseException()

        return self._inverse

    def open(self):
        """Marks a NetConnection as open for read / write"""

        if not self._inverse:
            raise self.NoInverseException("This error was raised because the NetConnection was opened but was not connected to another node. Perhaps the connection has already been closed?")

        self.is_open = True

    def _handle_close(self):
        self._inverse = None
        self.is_open = False

    def close(self):
        """Writes out a close packet and then closes the NetConnection.
        A closed NetConnection undergoes certain cleanup functions cannot be reopened again, please use a new NetConnection instance for this."""

        self.write_out(self.Packets.CLOSE)
        self._handle_close()

    async def read_in(self, blocking=True) -> str | None:
        """Reads in a packet from the NetConnection read buffer

        Returns:
            str: packet
        """

        if not self._read_buffer:
            if blocking:
                await self._read_event.wait()
            else:
                return None

        s = self._read_buffer.pop()
        if not self._read_buffer:
            self._read_event.clear()
            self.in_waiting = False
        
        if s == self.Packets.CLOSE:
            self._handle_close()
            return '' if blocking else None
        return s

    def write_out(self, out):
        """Writes out a packet to the read buffer of the corresponding NetConnection

        Args:
            out: Any
                Packet to write out. Will cast to string first.

        Raises:
            NetConnectionClosedException: if the NetConnection is closed
        """

        if not self.is_open:
            raise self.NetConnectionClosedException("Cannot write to a closed NetConnection!")

        try:
            add_async_task(self._write_to_inverse(out))
        except Exception as e:
            pass

    async def _write_to_inverse(self, out: str):
        await network.delay()
        self.get_inverse().receive_packet(str(out))

    def receive_packet(self, pkt: str):  
        self.in_waiting = True
        self._read_buffer.append(str(pkt))
        self._read_event.set()