# Overview

mwc713 currently inherits its address format from wallet713's implementation of the grinbox address format. While this format is very useful it has some shortcomings. Most notably, if a user doesn't change his address on each transaction, the operator of the mwcmq server
will know which addresses transact with one another. While amounts will still be unknown, this is certainly not ideal. While it's
possible for the user to proactively switch addresses each time he receives a payment, a protocol for automatically changing
addresses would be desireable. At the same time, to the end user this protocol for switching addresses must be completely
transparent. All that the end user of mwc713 should know is that they are using a v2 address vs. a v1 address and the
protocol would remain completely backwards compatible. This document will outline one possible way to acheive these goals.

# Index by time instead of index by specification

The current implementation of mwc713 allows the user to specify a different index on startup or after startup which tells
the application to listen to a different mwcmq address. While this is a useful privacy tool, the user must proactively use
it or the operator of the mwcmq server will be able to know their transactions. To counteract this, we are proposing a v2
address format that, while specifying a single address to users maps to diffierent underlying addresses that are actually
used on the mwcmq server. The idea is that if user wants to use a v2 address, to the user this address might look something
like this: mwcmq2://q5ZwKof1p2UneCJwka66ERDCaxASec79vfSFmk4hYNyDufSuNnyu. The user can send this address to another user
and transact as normal, but the underlying mwc713 instances of both users actually translate this address to a different
underlying mwcmq address before completing the actual underlying transaction. This is done by having a predefined hashing
procedure that is understood by both the sender and the recipient. This procedure would be the following:

<mwcmq address> = hash(<mwcmq2 address>_<floor of the number of days since January 1st 1970 utc time>)

So for example, user A might tell user B that their v2 address is:
mwcmq2://q5ZwKof1p2UneCJwka66ERDCaxASec79vfSFmk4hYNyDufSuNnyu
On Monday, both user A and user B's mwc713 instance can compute the hash of
(q5ZwKof1p2UneCJwka66ERDCaxASec79vfSFmk4hYNyDufSuNnyu_17885) is
q5Zti2gpfGMRudDpqQaEU7Rp8KjLc76zcRj4Vqtymy3qe5xx1Soe
and on Tuesday, both user A and user B's mwc713 instance can compute the hash of
(q5ZwKof1p2UneCJwka66ERDCaxASec79vfSFmk4hYNyDufSuNnyu_17886) is
q5Wr9f92djvFHLdTzNxSnoS83MUV53nXttyS79HFAVStYFV45ngH
and on Wednesday they both could similarly compuete a different hash value and know to send and recieve on this different
address. In this way, all user A and B have to know is that user A's mwcmq2 address is
mwcmq2://q5ZwKof1p2UneCJwka66ERDCaxASec79vfSFmk4hYNyDufSuNnyu
Their mwc713 instance will automatically be able to compute the correct address to both listen to and send to.

# Listening and sending

mwcmq addresses look like this: mwcmq://xmg2TtJjkiwh5i699kCXq2MBHYdiTdQ5UNWx8ksD5Q7zCG5zCZtP for testnet and
mwcmq://q5ZwKof1p2UneCJwka66ERDCaxASec79vfSFmk4hYNyDufSuNnyu for mainnet. Since mwcmq:// is the default address type, if the
mwcmq:// is not specified, it is assumed, so both mwcmq://xmg2TtJjkiwh5i699kCXq2MBHYdiTdQ5UNWx8ksD5Q7zCG5zCZtP and
xmg2TtJjkiwh5i699kCXq2MBHYdiTdQ5UNWx8ksD5Q7zCG5zCZtP refer to the same address. When mwc713 starts up, it listens to a mwcmq
address. An index parameter can be specified either on startup or after startup to start listening to a new address.
As stated in the overview, with the v2 address format implementation mwcmq would remain backwards compatible,
so nothing would need to change and mwcmq would operate as it does today, but we would add a parameter to the
configuration file to allow it to start a v2 address listener. This parameter is called "v2_enabled". If the config file
specified "v2_enabled = true" the mwc713 instance would be listening to a v2 address as opposed to the standard address
that is used currently. As defined the previous section, the mwc713 client would know to start listening to a new address
when the next day starts. Similarly the sending client would take this mwcmq2 address as an input and since it has access
to the current day, it would be able to quickly compute the proper hash to know which actual address the listener of the
recipient would be listening on. Everything would be backwards compatible so if a regular mwcmq address was specied the
mwc713 client would operate as before.

# Logics around listening

One of the new requirements that clients would have is that their time would need to be set, at least somewhat accurately.
It would be fairly simple to make mwc713 listen to the old address for some sort of grace period since it's not very
expensive to make two connections to the mwcmq server for a few minutes (maybe even up to an hour) instead of a single
connection, as v1 addresses require. This would allow for slight variations in time set by client and server.

# Privacy chacteristics

This is not a totally bomb proof privacy solution but it is significantly better than the current situation where the mwcmq
server operator knows who transacts with who, unless those users change their address. It should be noted that users would
still use the same address for the entire day so if multiple transactions were done in the same day, the operator would know
who the participants were. This can be counteracted by making the timeframes smaller. Hours are probably fine to use as well.
Additionally, an index number could be introduced to the hash so that each user listens to multiple addresses and can iterate
through them for additional intra-timeframe privacy. But one issue is that if the mwcmq server operator is a participant in
a v2 transaction, he would be able to calculate every transaction of that participant. That's not good, but since mwcmq uses
a federated model, the idea is that there would be different mwcmq server operators so interacting with any particular one
would be less likely.
