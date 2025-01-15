A network emulator tool built to explicitly document the protocols of a scalable blockchain alternative and to security test against bad actors.
The network operates on a zero consensus assumption and distributes validation redundantly. The network is byzantine fault tolerant as nodes will
lazily reach a strong eventual consensus for a members of a decentralized subnetwork entrusted to verify transactions. Nodes within the subnetwork
must provide proof of stake or proof of identity, but stake can be greatly discounted as redundant validation requires only 1 node (out of potentially hundreds)
to follow the standard protocol in order to remain secure. This also means it is overwhelmingly game theory suboptimal to attempt to cooperate with other nodes
using a non-standard protocol (prisoners dilemma with N>>1 other prisoners). Casino-style statistical analysis of subnetwork responders prevents manipulation of the chosen
verifiers.

Handling consensus this way has the benefit of:
1) Allowing transactions to be truly anonymous. Details of transactions do not need to be agreed upon.
2) Allowing the network to operate at scale. If a node running blockchain must be aware of every other node on the network it can be said to running in O(n),
and thus have to scale with the total number of nodes in the network. The entire network can be said to run in O(n<sup>2</sup>). In contrast, tracking
join/leave events of a constrained subnetwork runs in O(1).

<h2>(In)Frequently Asked Question(s)</h2>

<b>Why did you write it like that? Are you stupid?</b>

The dialogue api is designed to be as accessible as possible to people with little to no prior coding experience. The primary function of this project is as documentation for a set of protocols and
hopefully limiting the control flow to a fluent interface helps people follow along purely based on the function names without knowing any additional python syntax.
Being able to separate the code into response/expect graphs also makes it easier to generate a visual representation of the dialogue trees to make parts of the protocol easier to explain.
I'm writing a VSCode plugin that should make it less awful. <br />
Also you're free to inherit from BaseDialogue instead if you want to use standard async await syntax anyway. Equivalent response/expect functions can be found in DialogueUtil.