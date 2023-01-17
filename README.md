# Tunnelbore

WireGuard® nat punching

## Problem
WireGuard® is great at securing a point to point connection, but that is it.
Connecting to a central server, that routes the traffic between leaf nodes, is not always desirable.
The router sees unencrypted traffic and the route the traffic takes is probably suboptimal.

But direct connections are only stable, if both sides have static ip addresses.
Even if one side changes the ip, that information needs to get to the other side.
WireGuard® will only convey that information to the peer, if that node sends traffic.
So normally silent servers with roaming ips are usually not possible.

Also it is very hard to configure two (possibly roaming) peers, that try to reach each other regardless of the network they are in on the fastest route.

## Concept
The idea of this project is to let WireGuard® do, what it does best (creating point-to-point VPN connections) and to concentrate on where traffic should go around it.
With the help of some kind of introduction server, two nodes can reach each other via said server and learn candidate ip addresses of the other node.
This information can be used to establish to connect to the peer using ICE.

### How to grab traffic?
Assuming the software has access to the WireGuard® private key pair and knows the list of possible peers:

#### Outbound connections
Open a local UDP port to set as an endpoint for peers in the local WireGuard®.
Whenever we see packets on this port (usually only `first message`s of the handshake, if something else, drop it), test the `mac1` field for all possible pubkeys of the peers to identify the peer.
Do the nat punching with that peer and forward the `first message` to it.
Responses can be identified by remote ip/port pair.
In case we get one (`second message`) look the sending peer up and choose local ip/port for that peer.
(Ipv4 127.0.0.0/8 allows to reuse some ports here, ipv6 has only one loopback address)
Forward the `second message` to the local WireGuard® with the selected local ip/port as source.
WireGuard® will thus learn the selected local ip/port as an endpoint for the peer and will send all subsequent messages there.
When we receive messages from the selected ip/port we can simply do a lookup and see for which peer we have selected it for.
We can then forward the message to that peer.
Messages from the internet can then be mapped by their remote ip/port on the locally selecten ip/port and forwarded accordingly.

#### Inbound connections
(Possibly after we did Nat punching with some peer)
Receive `first message` of the handshake.
We have the private key, so we can decrypt it to learn the pubkey of the peer.
(TODO: Do we need to decrypt? If every ingoing connection does NAT punching, maybe we can build the maps at that time, so this - and access to the privkey - is unnessecary)
Now that we have indentified the peer, choose a local ip/port and forward the message using that as the source to the local WireGuard®.
The `second message` will be received on that ip/port, so we can identify the corrisponding peer and forward the message to it.
Continue the same, as for outbound messages.

#### Subsequent handshakes for rekeying
If the WireGuard® sees traffic it will usually rekey regularly (every 90 seconds or so).
These rekeys are implemented as a new handshake.
We can try to forward those packets without the logic from above, because we already know the propper mapping.

### How to detect if the peer has roamed?
If we forward subsequent handshake packets, we need to implement a timer, that checks, if `first message` is answered in time.
If not we must assume, that the peer is gone or has roamed, so we need to fall back to the logic from above and reattempt UDP nat punching against new candidates.

## We have to have access to the privkey, what can we do with that?
Theoretically we can compromise any connection using that key with it.
(TODO: It might make sense to use the key to verify connections with the introduction server, but that thought is not final.)
Practically the key is only used to decrypt the `first message` for ingoing traffic to identify the origin peer of that message.
We do forward the messages unaltered, so after the handshake everything is encrypted using ephemaral keys, that this software never had.

## Roadmap
- Implement a version without any nat punching, just redirection of traffic.
For this version no introduction server is needed, which delays some decisions.
Whenever we would usually collect candidate addresses of the peer and initiate ICE, simply re-resolve the hostname.
This is resolves the problem, that WireGuard® usually will only resolve hostnames once, so roaming of the peer can only be detected, when the peer tries to send traffic to us.
- Version 1:
Add a single connection to some kind of introduction server and coordinate ICE through that.
- Provisioning of WireGuard®, that does not rely on security of a single node.
Maybe use a CA and certificates to establish trust in the configuration.
- eBPF?

## Future expansion

### eBPF
It should be possible to only forward the handshake messages through user space and configure some BPF maps.
All data traffic could then be forwarded in the kernel using eBPF.
The best thing about is, is that the userspace implementation can stay in place, it will simply see no traffic with this change.
