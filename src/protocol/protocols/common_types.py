from dataclasses import dataclass

@dataclass(frozen=True)
class NodeData:
    '''The public node data for any node on the network'''
    address: int
    public_key: str

@dataclass(frozen=True)
class VerificationNodeData(NodeData):
    '''The public data for verification nodes on the network'''
    timestamp: float
    paused: bool = False
