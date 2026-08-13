# Verified Capture Tool Recipes

These commands were checked against Parallels Desktop 26.4.0 and Wireshark 4.6.7 installed on the macOS host. Re-check `--help` when tool versions change.

## Parallels host commands

```bash
prlctl list --all --json
prlctl list -i -f <ID-or-NAME>
prlctl status <ID-or-NAME>
prlctl exec <ID-or-NAME> --current-user <verified-guest-command> [args...]
prlctl snapshot-list <ID-or-NAME> --json
prlctl capture <ID-or-NAME> --file <filename>
prlsrvctl net list --json
```

`prlctl capture` takes a VM screenshot. It does not capture packets.

Do not embed `--password` values. Do not invent guest shell, PowerShell, browser-install, binary-path, wait, timeout, remote-debugging, or headless flags.

`prlctl start`, `stop`, `reset`, snapshot creation/switch/deletion, and network mutation alter state; use only with explicit authorization after checking the action-specific help.

## Packet capture

Discover interfaces first:

```bash
dumpcap -D
```

Bounded, narrowly filtered capture:

```bash
dumpcap -i <interface> -f '<guest-to-fixture-capture-filter>' --autostop duration:<seconds> -w <output.pcapng>
```

The filter is mandatory and uses libpcap syntax. It must constrain traffic to the selected guest and authorized fixture, for example with verified host literals. Never assume interface names such as `en0`, `vnic0`, or `eth0`. Capture permission failures must be fixed at the host; do not silently rerun as an unrelated privileged user.

## TShark analysis

```bash
tshark -r <capture.pcapng> -Y 'tls.handshake.type == 1'
tshark -r <capture.pcapng> -o 'tls.keylog_file:<external-keylog>' -Y 'http2'
tshark -r <capture.pcapng> -T json
tshark -r <capture.pcapng> -T fields -e <field> -E header=y
```

Use `-2 -R '<read-filter>'` only when a two-pass read filter is actually needed. `-R` without `-2` is invalid.

Relevant locally verified fields include:

```text
tls.handshake.type
tls.handshake.extensions_server_name
tls.handshake.ciphersuite
tls.handshake.extension.type
tls.handshake.extensions_supported_group
tls.handshake.sig_hash_alg
tls.handshake.extensions_alpn_str
http2.type
http2.flags.ack.settings
http2.streamid
http2.settings.id
http2.settings.header_table_size
http2.settings.enable_push
http2.settings.max_concurrent_streams
http2.settings.initial_window_size
http2.settings.max_frame_size
http2.settings.max_header_list_size
http2.settings.extended_connect
http2.settings.no_rfc7540_priorities
quic.long.packet_type
frame.time_epoch
tcp.stream
```

## Playwright MCP

Use only after proving which browser process the MCP controls:

```text
browser_navigate({url})
browser_snapshot({filename?})
browser_network_requests({static, filter?, filename?})
browser_network_request({index, part?, filename?})
browser_console_messages({level, all?, filename?})
browser_take_screenshot({filename?, fullPage?, scale})
browser_close()
```

The inspected MCP surface does not provide a verified browser launch, executable-path, guest attach, CDP connect, proxy, or user-data-directory operation. Do not invent one.
