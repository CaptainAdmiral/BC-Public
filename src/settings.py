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

NETWORK_DELAY = 0.2
"""The average delay in seconds it takes for a net connection to successfully propagate a packet to the target node"""

NETWORK_DELAY_VARIABILITY = 0.1
"""The ratio of standard deviation of the network delay to the mean delay

e.g a value of 0.1 will result in a standard deviation that's 1/10th of the mean delay"""

# Protocol
BASE_TIMEOUT = 15
"""Maximum number of seconds to wait for a response before timing out"""

MIN_CONNECTIONS = 100
"""The minimum number of nodes a node is allowed to know about to be considered a part of the network.
This is enforced to provide fault tolerance for distributed broadcast protocols."""

ACTIVE_RATIO = 0.5
"""What fraction of the network is probably active right now"""

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

TIME_TO_CONSISTENCY = timedelta(days=2).total_seconds()
"""Time until vnt reaches eventual consistency. Newer events are ignored when comparing verification network timelines
as they may not have had a chance to propagate through the network yet. This variable is for how far back events should be ignored."""

TRANSACTION_WITNESSES = 10
"""How many other nodes are chosen to redundantly store information about the transaction for validation"""

VERIFIER_REDUNDANCY = int(TRANSACTION_WITNESSES / 1.9) + 10
"""Minimum number of witness responses confirming a transaction occurred."""

STAKE_AMOUNT = 1_000_000
"""How much each node needs to put up for their proof of stake,
losable if they fail to properly validate transactions due to running a non standard protocol"""

NODE_0_PUBLIC_KEY, NODE_0_PRIVATE_KEY = (
    """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs/t2n8tJ52qyhfkykjHqV0+nfUM4xe9B5R/GSWg+z9uagBgWdnSt9P4md1pD299D0y87ZI/Y84SFKZaivprSLHQocoI1CJbVI3EmilRek6Pf2N2A7vB27venwB2inBa+0R1SjWThzsCir53/V1fVLBXQZNvAJbJVcfIAG7xsJiGeBYeM+GbtLnQqzkSlcjHr8M+voWhoqMHls1jRKctVh4HWIUPs0yNyt3b7Yw2uWwsx+uDxB97tL+950upI1dev1qUfb+cfgWzr4W9dbrqxywfzd4k0nfxFcGjy2s7sAXB0Ax4vUjt1gwebfauvNHsVmRYGB/Qv+vOj6mC020iTxQIDAQAB
-----END PUBLIC KEY-----""",
    """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCz+3afy0nnarKF+TKSMepXT6d9QzjF70HlH8ZJaD7P25qAGBZ2dK30/iZ3WkPb30PTLztkj9jzhIUplqK+mtIsdChygjUIltUjcSaKVF6To9/Y3YDu8Hbu96fAHaKcFr7RHVKNZOHOwKKvnf9XV9UsFdBk28AlslVx8gAbvGwmIZ4Fh4z4Zu0udCrORKVyMevwz6+haGioweWzWNEpy1WHgdYhQ+zTI3K3dvtjDa5bCzH64PEH3u0v73nS6kjV16/WpR9v5x+BbOvhb11uurHLB/N3iTSd/EVwaPLazuwBcHQDHi9SO3WDB5t9q680exWZFgYH9C/686PqYLTbSJPFAgMBAAECggEACCtEHirFWwmAJVhjHSNtWhL9jJAExL0gOJ9UKhL0c42UNLdYgP4OQuYB28h0dzIUxhd+eAkXD9nRC8sbGLt2XySoN6b6c75ELx83YITFpH4GDrXiYICjEU5we3s3h8340WJ7PlDYy+rOki8saVaNUHqD/SlD48zKl95OoXOlqqb9DOA1l8PFe94RFqNzeqa9Bw0UniwoCj3ot8wd936m3ur20efYMW/HDnXBx4mjBe0A1ib+xFkmR9x1vnqtVGdGNHVmloWnHWhoW3012W1ntFfBglUR8SyBhspjlcg+Rto6yKL9NoVVgACfI+zNIPVJe52T7108oZ6DTuqOR/swgQKBgQD8sxKZaHLz5wXQ2EysGZPRED2K88Gxz/gFdoyX7BSJBi3GGmRtpZgLBNlBmil8axh3KHniifeMC/XCsbvYkeM8F3xM1hCF3Z/Ygv5gNPZZ7orUEnPndE15/rgqDhrsew/KomAD6cztgyfws9eCwAgakcsZcIUGKOZpr8VQszl7RQKBgQC2VUDHW2xuwbbc4x/ux8Uj9BOEOMTljw8WhJo2gZI/iw96ojOfHJBnin+VT9oKqKLOLCxMFxSootFoVI9wsi15Oj3A23Cwvg4sZoSrGIoPdh7wpBh7zygeTc133Vl2Z6GXWiZh9NMFkHvqZh25R+0dj/C4HN3RjegOAY8sxaf+gQKBgQD3C/7H+cRATQBzj7NNoWfQwQbZvLsFomNAvAhxUj01RNQlU5IRXA4L376ikxux5mWxwOGAJw/bW6n1oJsb/GxiSDeeSr02klf+bPpRhhW+ECardCraAerotKzJeKa7wQfMO/iQetd88Hdwq/GqgyCpERW1FjsGrZ+tfUjzP3SX3QKBgQCSCBvWz2E8H8geh4YGz1cUYaLT7ke8d+Skq1V7vDDu1ahzFr/zeoQpeWKPqqG+kau7JuPfmUjBe43uWnN71ijXhA77jIVn+QAPDZjKE+BXW8qR/0tgtdyy0Kt0igLh80QXnWtKXzQ3q62jYWADChld6O/p9ayu7lHiDdunBzNygQKBgHehZpJO0p5SkMYyB5hDY8C7SHHerDZMq8T+4LAhiGKfuT0dwJSgXq5YbP8+2zq4pEsS7Lgu4JSi+UHOGXcvQlAlTm++LlSwmFTTc/OJoHJxJ96Zj4Mdfmvl0q/QYL0VIfqhTRciF2dC/85vx50+GjRSFP4zFbluy5GMdxcgRH56
-----END PRIVATE KEY-----
""",
)
