# Next update cycle

## Single PC diagnostics — planned

Requested for the next update. Implementation is deferred; this entry records the scope only.

Add a **Single PC** button that runs useful diagnostics without another computer running Elka or a pairing code. Keep the existing **Check both PCs** workflow available.

Planned checks:

- Network adapter, link status, IP configuration, gateway, routes and DNS settings.
- Outbound ping to the gateway and a selected destination, plus DNS and outbound connection checks.
- Local TCP and UDP socket checks, listening ports and application ownership.
- Windows firewall/filtering information, adapter bindings, driver information, interface errors and relevant event logs.
- Local packet evidence where available, with clear progress and explanations for administrator prompts.

Present plain-language results and recommend the next useful check or evidence-supported repair. Explain what passed, what failed and what could not be checked. Preserve the existing restore-point and recovery safeguards for repairs; Wireshark/Npcap installation remains exempt from the restore-point requirement.

Single PC mode must not start coordinated tests with another Elka endpoint. Normal outbound probes to the selected gateway, DNS service or test destination are part of this mode and should be explained in the interface.

A successful local socket test or ping reply does not prove that a different computer can initiate incoming traffic or that a packet travels through every receive-side filtering layer. Mark those checks as requiring an outside sender rather than reporting an unsupported pass or failure.

No implementation, build or release is requested at this time.
