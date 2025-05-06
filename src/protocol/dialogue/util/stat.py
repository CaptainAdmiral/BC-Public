import numpy as np
from numpy.typing import NDArray
from scipy.stats import binom
from functools import cache

from protocol.dialogue.base_dialogue import DialogueException
from settings import STATVAL_PROB_CUTOFF, TRANSACTION_WITNESSES, VERIFICATION_ACTIVE_RATIO

class StatTestFail(DialogueException):
    ...

def check_total_skipped(skip_array: NDArray[np.bool_]):
    '''Checks that the total number of skipped nodes is statistically plausible'''
    prob = binom.sf(np.sum(skip_array==True), TRANSACTION_WITNESSES, 1-VERIFICATION_ACTIVE_RATIO)
    
    if prob < STATVAL_PROB_CUTOFF:
        raise StatTestFail('Implausible number of skipped nodes')

@cache
def _prob_n_runs_or_more(n, run_len):
    '''The probability of finding a consecutive sequence of length run_len at least n times.
    Simplifies by treating sequences as independent to avoid monte carlo methods.
    Cached because these values should be a lookup table'''
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

    if agg_prob < STATVAL_PROB_CUTOFF:
        raise StatTestFail('Implausible number of consecutive skips')