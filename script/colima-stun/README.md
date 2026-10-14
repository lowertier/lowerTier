# Colima STUN and QUIC hole-punch experiment

Run:

```sh
COLIMA_DOCKER_CONTEXT=colima-lowertier-l2 script/colima-stun/e2e.sh
```

The QEMU lab creates one rendezvous network, two isolated private networks, and two cone-style NATs.
It adds start-time skew, 8% packet loss, and variable delay on both NAT uplinks.
The retained tracker serves STUN on two local UDP ports.
LowTier establishes a direct QUIC path and sends 20 overlay pings.

The script prints direct setup time, STUN observations, the peer-reflexive
endpoint selected by the puncher, packet loss, and RTT statistics.
