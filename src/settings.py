from datetime import timedelta

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

STATVAL_PROB_CUTOFF = 0.00001
'''The minimum probability of a transaction being legitimate before it's rejected.
Another way to read this is that ~1 in (1/n) legitimate transactions will be rejected by the protocol for the sake of security'''

VERIFICATION_CUTOFF = timedelta(days=2).total_seconds()
'''Newer events are ignored when comparing verification network timelines as they may not have had a chance to propagate through the network yet.
This variable is for how far back events should be ignored.'''

TRANSACTION_WITNESSES = 100
'''How many other nodes are chosen to redundantly store information about the transaction for validation'''

VERIFIER_REDUNDANCY = int(TRANSACTION_WITNESSES / 1.9) + 10
"""Minimum number of witness responses confirming a transaction occurred."""

STAKE_AMOUNT = 1_000_000
'''How much each node needs to put up for their proof of stake,
losable if they fail to properly validate transactions due to running a non standard protocol'''