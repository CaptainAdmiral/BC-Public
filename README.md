# What?

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

# Quick Setup

Grab a copy of python 3.12.x and pip install -r requirements.txt  
Running main.py will spin up a network and call any code you add to the run() function from inside run.py  
Running with the --verbose flag will enable verbose output (logs every packet sent on the network)  
Running with the --soft-crash flag will enable graceful shutdown of the program on crash (useful for running with a profiler)  

# Why?

The blockchain protocols are an incredible tool for creating decentralized networks, but they're horribly inefficient and fail to deliver on some of their key promises.
For example Bitcoin is supposed to be decentralized but single entities have surpassed 50% of the compute of the network on multiple occasions (GHash.io in 2014, AntPool + FoundryUSA in 2024 etc).

Furthermore they don't scale very well, as the number of transactions per unit time and the amount of compute keeping those transactions secure both scale with the number of people on the network. Each new node increases the total compute, storage, and network requirements exponentially.

Finally they lack any kind of privacy, as validating a shared distributed ledger of every transaction requires your entire "banking history" visible to everyone on the network.

This protocol fixes all of these issues and allows for a distributed network that's private, scalable, and environmentally conscious.
The protocol is so efficient in fact that it makes it possible to run a simulation of every device on a full scale network from one machine (hence this project)
For comparison simulating a proof of work network like Bitcoin would require more energy per unit time than is consumed by the country of Bangladesh.
Simulating a proof of stake blockchain such as Etherium would require roughly the same energy as training 66 ChatGPT's per unit time.

# How?

The results described here are achieved by eliminating the need for consensus on a distributed ledger across the network. Rather than a consensus on every transaction the network reaches a lazy consensus on its members and validates transactions using statistical analysis. For a detailed look at how it works please see src/protocol/dialogue/dialogues.py for an outline of the protocol. An attempt was made to make it readable to non programmers, but I failed.



For business or academic enquiries (I encourage you to reach out if you have any questions) please contact mattb1197@live.co.uk