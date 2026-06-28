# Reference sources

This project intentionally takes inspiration from these upstream projects without copying their application code into the Kotlin shell:

- FoxIO-LLC/ja4: <https://github.com/FoxIO-LLC/ja4>
  - Used as a pinned Cargo git dependency for personal-use PCAP JA4 computation.
  - Requires `tshark` at runtime for PCAP processing.
- sleeyax/burp-awesome-tls: <https://github.com/sleeyax/burp-awesome-tls>
  - Used as architecture inspiration: Burp redirects traffic intent to a native local transport/proxy layer, profile settings are passed per request, and native binaries are packaged with the extension jar.
  - GPL-3.0 project; copy concepts, not source code, unless you intentionally accept license obligations.
