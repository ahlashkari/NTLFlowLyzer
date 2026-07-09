# UDP Flow Support

This patch adds optional UDP flow generation to NTLFlowLyzer through the existing
`ntlflowlyzer` command.

## User Story

As a security researcher processing malware sandbox PCAPs, I need a flow export
that includes both TCP and UDP traffic, so that downstream labeling, inventory
building, and family-level analysis can see the complete network behavior of a
sample.

The upstream parser emits TCP flows by default. For malware analysis this can
hide important behavior: UDP can carry DNS lookups, service discovery, C2
bootstrap traffic, or short-lived application traffic that helps explain later
connections.

The desired behavior is not to redefine every TCP feature for UDP. The desired
behavior is to keep the existing NTLFlowLyzer output shape usable while adding
UDP rows only when explicitly requested.

## Usage

Default behavior remains TCP-only:

```bash
ntlflowlyzer -c YOUR_CONFIG_FILE
```

To emit UDP flows in addition to TCP flows:

```bash
ntlflowlyzer --udp -c YOUR_CONFIG_FILE
```

The flag also works in batch mode:

```bash
ntlflowlyzer --udp -b -c YOUR_CONFIG_FILE
```

## Goals

- Keep TCP-only behavior as the default.
- Add UDP flows only when `--udp` is passed.
- Preserve the existing CSV columns as much as possible.
- Avoid a separate package name or a separate console command.
- Make non-applicable TCP-only UDP values explicit and reviewable.

## Non-Goals

- This patch does not add UDP-specific statistical features beyond what the
  existing packet/flow model can already calculate.
- This patch does not reinterpret TCP handshake, TCP flag, TCP window, sequence,
  or acknowledgement features for UDP.
- This patch does not add DNS, QUIC, DTLS, or application payload parsing.
- This patch does not change TCP flow extraction when `--udp` is not used.

## Implementation

Files:

- `NTLFlowLyzer/__main__.py`
- `NTLFlowLyzer/network_flow_analyzer.py`
- `NTLFlowLyzer/network_flow_capturer/network_flow_capturer.py`
- `NTLFlowLyzer/feature_extractor.py`

The CLI adds:

```text
--udp
```

The flag is passed from the CLI to `NTLFlowLyzer`, then to
`NetworkFlowCapturer`.

When `--udp` is not passed, the capturer keeps the upstream TCP-only packet
filter.

When `--udp` is passed, the capturer accepts:

- `dpkt.tcp.TCP`
- `dpkt.udp.UDP`

For TCP packets, the existing fields are preserved:

- source and destination ports
- TCP flags
- sequence number
- acknowledgement number
- TCP window size
- TCP payload length
- transport header length

For UDP packets, the capturer creates a normal `Packet` object using:

- UDP source port
- UDP destination port
- UDP payload length
- UDP header length

UDP has no TCP flags, sequence numbers, acknowledgements, or advertised receive
window. Those packet fields are filled with neutral zero values to keep the
existing schema stable:

- `window_size = 0`
- `tcp_flags = 0`
- `seq_number = 0`
- `ack_number = 0`

## TCP-Only Features On UDP Rows

Some derived features are meaningful only for TCP. For UDP flows, this patch
emits `NaN` for those features instead of logging repeated extraction errors or
fabricating numeric values.

Currently treated as TCP-only:

- all features from the `flag_related` feature module
- `delta_start`
- `handshake_duration`
- `handshake_state`
- `fwd_init_win_bytes`
- `bwd_init_win_bytes`

All non-TCP-specific features continue to be extracted normally for UDP flows.

## Compatibility Notes

- `ntlflowlyzer -c YOUR_CONFIG_FILE` remains TCP-only.
- `ntlflowlyzer --udp -c YOUR_CONFIG_FILE` emits TCP and UDP flows.
- TCP behavior is intended to stay unchanged.
- Downstream consumers should treat `NaN` TCP-only feature values on UDP rows as
  "not applicable".
- Existing CSV columns remain present so downstream tooling does not need a
  separate UDP schema branch.

## Review Notes

Suggested review focus:

- Confirm TCP code paths still use the same packet fields as upstream.
- Confirm UDP is gated behind `--udp`.
- Confirm UDP packet fields use UDP ports, payload length, and header length.
- Confirm TCP-only features are the only features forced to `NaN` for UDP.
- Confirm the default command remains TCP-only.
