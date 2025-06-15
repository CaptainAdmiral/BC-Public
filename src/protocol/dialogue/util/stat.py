from typing import TYPE_CHECKING, Iterable
import numpy as np
from numpy.typing import NDArray
from scipy.stats import binom
from functools import cache

from protocol.dialogue.dialogue_types import DialogueException
from settings import MIN_P_MISSING_EVENT, STATVAL_P_CUTOFF, TIME_TO_CONSISTENCY, TRANSACTION_WITNESSES, VERIFICATION_ACTIVE_RATIO

if TYPE_CHECKING:
    from protocol.verification_net.vnt_types import VerificationNetEvent

class StatTestFail(DialogueException):
    ...

def check_total_skipped(skip_array: NDArray[np.bool_]):
    '''Checks that the total number of skipped nodes is statistically plausible'''
    prob = binom.sf(np.sum(skip_array==True), TRANSACTION_WITNESSES, 1-VERIFICATION_ACTIVE_RATIO)
    
    if prob < STATVAL_P_CUTOFF:
        raise StatTestFail('Implausible number of skipped nodes')

@cache # Cached because these values should be a lookup table
def _prob_n_runs_or_more(n, run_len):
    '''The probability of finding a consecutive sequence of length run_len at least n times.
    Simplifies by treating sequences as independent to avoid monte carlo methods.'''
    p = (VERIFICATION_ACTIVE_RATIO - 1) ** run_len
    k = TRANSACTION_WITNESSES - run_len + 1
    
    probability = binom.sf(n - 1, k, p)
    return probability

def check_consecutive_skips(skip_array: NDArray[np.bool_]):
    '''Finds the approximate probability of the sequence being legitimate based on the
    lengths of all the runs of consecutive skips'''

    chains: dict[int, int] = {}
    chain_len = 0

    for skip in skip_array:
        if skip:
            chain_len += 1
        else:
            if chain_len > 0:
                if not chain_len in chains:
                    chains[chain_len] = 0
                chains[chain_len] += 1
            chain_len = 0

    agg_prob = 1
    for chain_len, count in chains.items():
        agg_prob *= _prob_n_runs_or_more(count, chain_len)

    agg_prob *= 1/(1-VERIFICATION_ACTIVE_RATIO) # Approximation of series at limit for TRANSACTION_WITNESSES >> 1

    if agg_prob < STATVAL_P_CUTOFF:
        raise StatTestFail('Implausible number of consecutive skips')

def check_missing_events(missing_events: Iterable['VerificationNetEvent'], timestamp: float):
    """Checks whether the events unknown to all parties at the time of transaction are statistically plausible"""
    
    p = 1
    for event in missing_events:
        p_seen = (timestamp - event.timestamp) / TIME_TO_CONSISTENCY
        p_missed = min(1 - p_seen, MIN_P_MISSING_EVENT)
        p *= p_missed

    if p < STATVAL_P_CUTOFF:
        raise StatTestFail('Implausible collection of skipped events')