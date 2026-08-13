# Browser Profile Differential Report

## Verdict

`BLOCKED`

## Scope

- Canonical profile:
- Real browser full version:
- Guest OS/architecture:
- Authorized fixture:
- Real capture:
- Emulated capture:
- Fresh-connection policy:
- Selected real flow (client/server 5-tuple, SNI, TCP stream):
- Selected emulated flow (client/server 5-tuple, SNI, TCP stream):
- Dedicated process command:

## Identity and provenance gates

| Gate | Result | Evidence |
|---|---|---|
| Exact browser binary version measured | | |
| Captured traffic linked to target browser | | |
| Real and emulated endpoint/path equivalent | | |
| Playwright target placement proven or excluded | | |
| Both captures isolate client SETTINGS from server/ACK frames | | |
| Every exposed platform has measured identity headers | | |

## Comparison

| Dimension | Class | Real | Emulated | Result | Evidence |
|---|---|---|---|---|---|
| TLS cipher order | exact | | | | |
| TLS extension order | normalized | | | | |
| Supported groups | exact | | | | |
| Signature algorithms | exact | | | | |
| ALPN | exact | | | | |
| JA3/JA4 | normalized | | | | |
| HTTP/2 SETTINGS | exact | | | | |
| HTTP/2 pseudo-header order | exact | | | | |
| User-Agent and Client Hints | exact | | | | |
| Request headers/order | exact | | | | |

## Normalization rules

- None recorded.

## Controlled failure path

- Input:
- Expected failure:
- Observed failure:
- Result:

## Mismatches

- None recorded.

## Unavailable evidence

- None recorded.

## Commands and manual QA

- Commands:
- Live request result:
- Tests:

## Residual risks

- This report measures protocol fidelity only. It does not assess or claim anti-bot/WAF evasion or human indistinguishability.
