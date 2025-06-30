from datetime import timedelta

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Logging
_verbose = False


def set_verbose(val: bool):
    global _verbose
    _verbose = val


def get_verbose():
    return _verbose


LOG_DIALOGUES = True
"""Log whenever a new dialogue function is entered"""

# Cryptography
SIG_HASH = hashes.SHA256()
SIG_KEY_SIZE = 2048
SIG_PUBLIC_EXPONENT = 65537
SIG_PADDING = padding.PSS(
    mgf=padding.MGF1(SIG_HASH), salt_length=padding.PSS.MAX_LENGTH
)

# Network
TIME_SCALE = 1
"""How many simulated seconds pass for every real world second"""

UPDATE_RATE = 0.1
"""How many seconds to wait between updates"""

NETWORK_DELAY = 0.2
"""The average delay in seconds it takes for a net connection to successfully propagate a packet to the target node"""

NETWORK_DELAY_VARIABILITY = 0.1
"""The ratio of standard deviation of the network delay to the mean delay

e.g a value of 0.1 will result in a standard deviation that's 1/10th of the mean delay"""

# Protocol
BASE_TIMEOUT = 15
"""Maximum number of seconds to wait for a response before timing out"""

VERIFICATION_ACTIVE_RATIO = 0.9
"""What fraction of the verification network is probably active on right now"""

RNG_MOD_PK = 100000
"""The RNG for witness selection is based on the modulo of the public keys of the transaction participants. This
value changes the modulus applied to the public key"""

STATVAL_P_CUTOFF = 0.00001
"""The minimum probability of a transaction being legitimate before it's rejected.
Another way to read this is that ~1 in (1/n) legitimate transactions will be rejected by the protocol for the sake of security"""

MIN_P_MISSING_EVENT = 0.01
"""The floor for probability of having no knowledge of an event as time passes. No matter how much time has passed the probability of missing
an event will never be lower than this value."""

TIMESTAMP_LENIENCY = timedelta(hours=1).total_seconds()
"""The maximum acceptable difference between the reported timestamp and the current time"""

TIME_TO_CONSISTENCY = timedelta(days=2).total_seconds()
"""Time until vnt reaches eventual consistency. Newer events are ignored when comparing verification network timelines
as they may not have had a chance to propagate through the network yet. This variable is for how far back events should be ignored."""

ROLLOVER_PERIOD = timedelta(days=30).total_seconds()
"""How often to roll over the receipts for a transaction to new verification nodes."""

TRANSACTION_WITNESSES = 100
"""How many other nodes are chosen to redundantly store information about the transaction for validation"""

VERIFIER_REDUNDANCY = int(TRANSACTION_WITNESSES / 1.9) + 10
"""Minimum number of witness responses confirming a transaction occurred."""

STAKE_AMOUNT = 100_000_000
"""How much each node needs to put up for their proof of stake,
losable if they fail to properly validate transactions due to running a non standard protocol"""

GAS_AMOUNT = 1000
"""How much verifiers take in total per transaction"""

ENTROPY_RATE = 1e-9
"""The average number of times per second each node will emit an add entropy event"""

NODE_0_PUBLIC_KEY, NODE_0_PRIVATE_KEY = (
    """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApcjRvPmdyo44x+ISN8CT
8e0WXi4DVC+5bdcdCOMYI9NQqmZhJT1yr7w+qibs0+gbe+GX97L/QufApdzKVmdn
35SSytwwCCw8qRXWGYyMGbp2gGZ9tq3etH58r9X/daAURgzozzFYPG/fMxukQ4Bw
MGmJczAdt9kbP9vf+GCVytNmX1UO+X1RL2qxzmGr2tPVsnfchyazvZL6P4CiU3Rx
ru2qeS7c4zPfpb+HgGduOrxtjo8UOOnOeAH+kxMP71ksfbVdCKa70sjvIjpCLmva
ydPHzR3R+cHE4hPwxA76TS8Kn9WMHdWnIg9r57IVgrwyO+44qv5qhAqiSwiEmYuY
IwIDAQAB
-----END PUBLIC KEY-----
""",
    """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQClyNG8+Z3KjjjH
4hI3wJPx7RZeLgNUL7lt1x0I4xgj01CqZmElPXKvvD6qJuzT6Bt74Zf3sv9C58Cl
3MpWZ2fflJLK3DAILDypFdYZjIwZunaAZn22rd60fnyv1f91oBRGDOjPMVg8b98z
G6RDgHAwaYlzMB232Rs/29/4YJXK02ZfVQ75fVEvarHOYava09Wyd9yHJrO9kvo/
gKJTdHGu7ap5LtzjM9+lv4eAZ246vG2OjxQ46c54Af6TEw/vWSx9tV0IprvSyO8i
OkIua9rJ08fNHdH5wcTiE/DEDvpNLwqf1Ywd1aciD2vnshWCvDI77jiq/mqECqJL
CISZi5gjAgMBAAECggEAAKSnEG/z6uwM/UtivJYGqvW+ksal03aanm2CgDFpQbkO
bua1V4HNlVV3kU6rVAhzs1UhJrFvEo1Q6hrXrnVHuyRD6235Itp+QLrNdTeAoQ7s
iW3LMXpmZwtG00SkYbk16V0sgZxMp3IBXyx/cCWaky/ZVqDIznzG4kyTk/QSHr/2
y//C0bjb/Zad1ykJqNZt00a+vQz5CsWIR7YVf3kAvhqjFXpFBwDvp3HrQhptypzS
t36F53pBoC8tjxfotqgI/521Q7f58u8fFGagGJYPJtSERVgPhpzMD3Lu0VSvXbcL
N4xLbiPfoFOmcWnsXpEvFBdO3NO+u7da5mC5jfCPcQKBgQDl/aeX/0LCUDY1BRLM
xvGMBuadOZP0Zwl/5Lw7pkfjul5hf2I/yUnWUbzx39Al+DvCEpOV0zUG7CmDdnm3
TiFmIKWDbzsbOn83YohyTrGHQ1tDsw3SIU6qJh5G9ZXEFFBl6gN+GdcXZzUbR4MN
8o75Df1gWpcTWF4Tex7bbsP6cQKBgQC4iFvb3VEPRkaPTm8vs+jwPvPE+pbdmsse
BL5xqHVJMnFuKcjpqqTYrTQCufFBr4uloIcxe4LfcGqDT5Np3Vq/mvW+KAdvi6Gh
1VT/+lbZjIbOFir4y4nqj/vgxVwiSKo7f86KVIHifu+9aaDv3M3LJIn7uZkVFqM1
EMEMp+t90wKBgQDSUGSjkB9iRatsTJlmfT6BSAY3HGH6Cwca1vZyrZnr249XJP+Z
SN6mh9R6cqqLLjanQAmJ5rwE+ozz1LF1OJM+Kvhv+pVYTuPqp8YSkXeyM5wPintG
/oJLAdSKGyW7SsBCkf5joAmbMxvTOE/Vv0uS4IIlTHH+lL5iniIXk3DPYQKBgDuw
p/4Lrd/B/Kr4VRDaIjwsMNADuu891fwEztGXCzE9JuHalEm5UA9in1NOcFKuBP7z
WSfRavj5tQp6oBV7a5JU/q6e5iDXytW9WvxeLt+6DBT3qLjHpfoAzxna3T2dwarz
YYzvXwAzzTq4wz0zcEIItLV/SJxAsVRF8hw06QDPAoGBAJZesQSnYZcpC8goRKd0
Izmk/5lQYN2uMLSxJ0cvDt9zwmfFcR2mzcKZytxjQR67At+xgSOcI+53bRmDReg5
jTO2vdsD4DhsVg4UUfMak2IxFS4yZE88XGBaEytX39Un1+H5eAeCqvYDEaS6eI0h
8AXGNNDZbSvh2/9xq+vmLtRE
-----END PRIVATE KEY-----
""",
)
