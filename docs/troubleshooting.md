# Troubleshooting

Start with `sudo lowertier doctor`. It checks each layer in order and prints a fix for each problem:

```text
ok    daemon     default at 127.0.0.1:15888
ok    token      /opt/lowertier/config/control.token is readable
ok    portal     127.0.0.1:15888 answers
ok    instance   default is running
ok    listeners  h2://0.0.0.0:11010, quic://0.0.0.0:11012, wss://0.0.0.0:11012/ws
ok    nat        UDP Symmetric, TCP Symmetric, public 203.0.113.7
ok    peers      1 peer(s), 1 direct
```

| Symptom | What to check |
| --- | --- |
| `Cannot read the control token` | Run the command with `sudo`, or set `control.token_group` and restart the node. |
| `Several daemons are running` | Pick one with `-n NAME`. `lowertier nodes` lists them. |
| `lowertier check` reports renamed options | Edit the file as listed. Each message names the new path. |
| A peer stays unreachable | `lowertier peers`, `lowertier listeners`, `lowertier discovery`. Check that firewalls pass every listener port, or try an explicit `quic://`, `h2://`, or `wss://` peer URL. |
| Peers connect only through a relay | `lowertier discovery` shows NAT mappings. Two NATs that change ports per destination often cannot connect directly; see [NAT traversal](nat-traversal.md). |
| Large transfers stall | `lowertier doctor` reports loss. Try `lowertier set tun.mtu=1280 --stage`. |
| ARP, VLANs, or other Ethernet traffic does not cross | Both nodes need `l2.bridge = true` and a finite `l2.flood_bytes_per_second`. VLAN, QinQ, LLDP, and other EtherTypes need Linux or FreeBSD on both ends. |
| QUIC warns about socket buffers | Raise the host's UDP receive buffer limits, then restart the node. Inside a container that cannot change them, HTTP/2 still works. |

`lowertier logs -f` follows the log. `lowertier log-level debug` raises detail until you set it back.
