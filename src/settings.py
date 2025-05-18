from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import timedelta

SIG_HASH = hashes.SHA256()
SIG_KEY_SIZE = 2048
SIG_PUBLIC_EXPONENT = 65537
SIG_PADDING = padding.PSS(
    mgf=padding.MGF1(SIG_HASH),
    salt_length=padding.PSS.MAX_LENGTH
)

TIME_SCALE = 1
'''How many simulated seconds pass for every real world second'''

NETWORK_DELAY = 0.2 
'''The average delay in seconds it takes for a net connection to successfully propagate a packet to the target node'''

NETWORK_DELAY_VARIABILITY = 0.1
'''The ratio of standard deviation of the network delay to the mean delay

e.g a value of 0.1 will result in a standard deviation that's 1/10th of the mean delay'''

BASE_TIMEOUT = 15
'''Maximum number of seconds to wait for a response before timing out'''

MIN_CONNECTIONS = 100
'''The minimum number of nodes a node is allowed to know about to be considered a part of the network.

This is enforced to provide fault tolerance for distributed broadcast protocols.'''

BROADCAST_SPREAD = 50
'''How many nodes to initially broadcast to and rebroadcast to upon receiving a broadcast'''

assert(BROADCAST_SPREAD <= MIN_CONNECTIONS) # This should hold true as the probability of a broadcast rebroadcasting drops off as it propagates to match the increased number of sources propagating it.
                                            # This assertion should be met in order to ensure that poorly connected edge nodes have a fair change to receive broadcasts.

BROADCAST_DECAY = 0.8
'''The base probability of rebroadcast (increases geometrically with distance from origin)'''

BROADCAST_AGGREGATION_DECAY = 0.8
'''How much to degrade the probability of rebroadcast by for each additional broadcast received and aggregated'''

MAX_BROADCAST_LIFETIME = 600
'''The max lifetime of a broadcast in seconds'''

ACTIVE_RATIO = 0.5
'''What fraction of the network is probably active right now'''

VERIFICATION_ACTIVE_RATIO = 0.9
'''What fraction of the verification network is probably active on right now'''

RNG_MOD_PK = 100
'''The RNG for witness selection is based on the mod public key of the payer to add a little extra variation to the selected witnesses. This
value changes the modulus applied to the public key'''

STATVAL_P_CUTOFF = 0.00001
'''The minimum probability of a transaction being legitimate before it's rejected.
Another way to read this is that ~1 in (1/n) legitimate transactions will be rejected by the protocol for the sake of security'''

MIN_P_MISSING_EVENT = 0.01
'''The floor for probability of having no knowledge of an event as time passes. No matter how much time has passed the probability of missing
an event will never be lower than this value.'''

TIME_TO_CONSISTENCY = timedelta(days=2).total_seconds()
'''Time until vnt reaches eventual consistency. Newer events are ignored when comparing verification network timelines
as they may not have had a chance to propagate through the network yet. This variable is for how far back events should be ignored.'''

TRANSACTION_WITNESSES = 100
'''How many other nodes are chosen to redundantly store information about the transaction for validation'''

VERIFIER_REDUNDANCY = int(TRANSACTION_WITNESSES / 1.9) + 10
"""Minimum number of witness responses confirming a transaction occurred."""

STAKE_AMOUNT = 1_000_000
'''How much each node needs to put up for their proof of stake,
losable if they fail to properly validate transactions due to running a non standard protocol'''

NODE_0_PUBLIC_KEY, NODE_0_PRIVATE_KEY = (
    ''' -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs/t2n8tJ52qyhfkykjHq
    V0+nfUM4xe9B5R/GSWg+z9uagBgWdnSt9P4md1pD299D0y87ZI/Y84SFKZaivprS
    LHQocoI1CJbVI3EmilRek6Pf2N2A7vB27venwB2inBa+0R1SjWThzsCir53/V1fV
    LBXQZNvAJbJVcfIAG7xsJiGeBYeM+GbtLnQqzkSlcjHr8M+voWhoqMHls1jRKctV
    h4HWIUPs0yNyt3b7Yw2uWwsx+uDxB97tL+950upI1dev1qUfb+cfgWzr4W9dbrqx
    ywfzd4k0nfxFcGjy2s7sAXB0Ax4vUjt1gwebfauvNHsVmRYGB/Qv+vOj6mC020iT
    xQIDAQAB
    -----END PUBLIC KEY-----''',
    ''' -----BEGIN PRIVATE KEY-----
    MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCz+3afy0nnarKF
    +TKSMepXT6d9QzjF70HlH8ZJaD7P25qAGBZ2dK30/iZ3WkPb30PTLztkj9jzhIUp
    lqK+mtIsdChygjUIltUjcSaKVF6To9/Y3YDu8Hbu96fAHaKcFr7RHVKNZOHOwKKv
    nf9XV9UsFdBk28AlslVx8gAbvGwmIZ4Fh4z4Zu0udCrORKVyMevwz6+haGioweWz
    WNEpy1WHgdYhQ+zTI3K3dvtjDa5bCzH64PEH3u0v73nS6kjV16/WpR9v5x+BbOvh
    b11uurHLB/N3iTSd/EVwaPLazuwBcHQDHi9SO3WDB5t9q680exWZFgYH9C/686Pq
    YLTbSJPFAgMBAAECggEACCtEHirFWwmAJVhjHSNtWhL9jJAExL0gOJ9UKhL0c42U
    NLdYgP4OQuYB28h0dzIUxhd+eAkXD9nRC8sbGLt2XySoN6b6c75ELx83YITFpH4G
    DrXiYICjEU5we3s3h8340WJ7PlDYy+rOki8saVaNUHqD/SlD48zKl95OoXOlqqb9
    DOA1l8PFe94RFqNzeqa9Bw0UniwoCj3ot8wd936m3ur20efYMW/HDnXBx4mjBe0A
    1ib+xFkmR9x1vnqtVGdGNHVmloWnHWhoW3012W1ntFfBglUR8SyBhspjlcg+Rto6
    yKL9NoVVgACfI+zNIPVJe52T7108oZ6DTuqOR/swgQKBgQD8sxKZaHLz5wXQ2Eys
    GZPRED2K88Gxz/gFdoyX7BSJBi3GGmRtpZgLBNlBmil8axh3KHniifeMC/XCsbvY
    keM8F3xM1hCF3Z/Ygv5gNPZZ7orUEnPndE15/rgqDhrsew/KomAD6cztgyfws9eC
    wAgakcsZcIUGKOZpr8VQszl7RQKBgQC2VUDHW2xuwbbc4x/ux8Uj9BOEOMTljw8W
    hJo2gZI/iw96ojOfHJBnin+VT9oKqKLOLCxMFxSootFoVI9wsi15Oj3A23Cwvg4s
    ZoSrGIoPdh7wpBh7zygeTc133Vl2Z6GXWiZh9NMFkHvqZh25R+0dj/C4HN3RjegO
    AY8sxaf+gQKBgQD3C/7H+cRATQBzj7NNoWfQwQbZvLsFomNAvAhxUj01RNQlU5IR
    XA4L376ikxux5mWxwOGAJw/bW6n1oJsb/GxiSDeeSr02klf+bPpRhhW+ECardCra
    AerotKzJeKa7wQfMO/iQetd88Hdwq/GqgyCpERW1FjsGrZ+tfUjzP3SX3QKBgQCS
    CBvWz2E8H8geh4YGz1cUYaLT7ke8d+Skq1V7vDDu1ahzFr/zeoQpeWKPqqG+kau7
    JuPfmUjBe43uWnN71ijXhA77jIVn+QAPDZjKE+BXW8qR/0tgtdyy0Kt0igLh80QX
    nWtKXzQ3q62jYWADChld6O/p9ayu7lHiDdunBzNygQKBgHehZpJO0p5SkMYyB5hD
    Y8C7SHHerDZMq8T+4LAhiGKfuT0dwJSgXq5YbP8+2zq4pEsS7Lgu4JSi+UHOGXcv
    QlAlTm++LlSwmFTTc/OJoHJxJ96Zj4Mdfmvl0q/QYL0VIfqhTRciF2dC/85vx50+
    GjRSFP4zFbluy5GMdxcgRH56
    -----END PRIVATE KEY-----'''
)