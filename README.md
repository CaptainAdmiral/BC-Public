A network emulator tool built to explicitly document the protocols of a privacy-first, scalable alternative to blockchain and to security test against bad actors.
The network operates on a zero consensus assumption and distributes validation redundantly. The network is byzantine fault tolerant as nodes will
lazily reach a strong eventual consensus for a members of a decentralized subnetwork entrusted to verify transactions. Nodes within the subnetwork
must provide proof of stake or proof of identity, but stake can be greatly discounted as redundant validation requires only 1 node (out of potentially hundreds)
to follow the standard protocol in order to remain secure. This also means it is overwhelmingly game theory suboptimal to attempt to cooperate with other nodes
using a non-standard protocol (prisoners dilemma with N>>1 other prisoners). Casino-style statistical analysis of subnetwork responders prevents manipulation of the chosen
verifiers.

Removing the need for transaction consensus has the benefit of:
1) Providing privacy, the details of every transaction do not need to be made public.
2) Preventing deanonymization based on transaction history.
3) Allowing the network to operate efficiently and at scale, as the complexity grows linearly with more nodes instead of exponentially.