# Development

## Build

Windows, .NET SDK 8.0.425 (or later 8.0 patch), C# 12, WPF. There are no external NuGet library dependencies. Open `ELKA.Network.Diagnostics.sln` in Visual Studio or run:

```powershell
dotnet build ELKA.Network.Diagnostics.sln -c Release
dotnet run --project tests/Elka.NetworkDiagnostics.Tests -c Release --no-build
```

Append `-- --windows-inspection` to the test command to collect read-only local adapter, port, driver and firewall evidence. The test harness never invokes the elevated helper or changes network configuration.

`scripts/package.ps1` publishes both executables with the Windows x64 runtime, includes the user guide, creates a portable ZIP and writes its SHA-256 hash. Extract the whole folder; the helper and runtime files must remain beside the main executable. The binaries are not code signed.

The end-user entry points are README.md, SETUP.md and the browser-readable START-HERE.html. Guide PNGs and original SVGs live under `docs/images`; `scripts/build-guide-images.cjs` regenerates them with `sharp`. `scripts/build-guide-html.mjs` regenerates START-HERE.html from SETUP.md with `marked`. Both generators accept an optional installed-module path. Their generated files are committed, so normal application builds do not require Node. The portable package includes the HTML guide, Markdown copies, PNGs and the supplied .NET/Windows Desktop runtime notices under `third-party`.

## Large PktMon analysis (0.1.9)
<!-- Previous capture-analysis implementation remains in use. -->

`TraceTextReader` streams fixed 8-KiB character buffers, rejects lines beyond 16 KiB and limits work to 512 Mi characters (formerly 64 Mi). Both packet counting and UDP correlation use it. The limit measures decoded characters, independently of the 64-MiB ETL capture limit. `UdpPacketTrace` continues scanning after its 10,000 retained-detail budget, counts every supported match and prioritizes later explicit drops over ordinary retained observations. Any omitted detail or unread text is reported as partial, including the reason. An EOF at the exact limit remains complete.

The app performs correlation on a worker task with cancellation. Cancellation is enabled during this read after the helper has already stopped its owned capture; capture/repair cleanup is not interrupted. Capture availability and analysis completeness are separate assessment fields. Partial, cancelled and failed analysis remain visible in recommendations and the saved overview, and prevent optional QoS-trial suggestions. Completing text analysis does not imply continuous NIC visibility or supported decoding of every payload.

ZIP exports keep a 50-file/512-MiB aggregate budget, allow expanded PktMon text below 512 MiB, and preserve the existing under-100-MiB bound for other files. Source ETLs and compact companions take precedence. `captures-manifest.txt` lists included and size/count-omitted referenced files; oversized text can be regenerated from its ETL. This does not change the bounded session-only importer or TShark input limit.

## Components

Version 0.2.0 removes the role selector. The persisted and wire `Role` fields remain for backwards compatibility; new settings use `Endpoint`, and the app ignores the old preference when choosing tests. Peer commands and protocol version are unchanged. `TwoPcCheck` projects the selected address/port scope into four directional rows; stale or unrelated traffic cannot create a result. Failed samples remain visible after later passes. Missing results remain unknown, separately from verified zero delivery. `TestAttemptException` carries partial structured observations when preparation or result exchange fails. TCP acknowledgement/completion errors with full receiver delivery do not focus blame on the receiver.

The new quick-check command runs authenticated control probes plus both UDP/TCP directions and saves a scoped assessment without elevated operations. Full scans retain all eight stages and publish an initial two-PC result after stage 3. The summary table, saved `PacketPathReport.Directions`, and support output share the same projection. Old saved path reports without `Directions` still load. Deep inspections and capture approvals remain local; no remote admin RPC was introduced.

- `Core`: evidence, settings, persistent sessions, bounded reports and offline import.
- `Network`: authenticated control messages, bounded RPC, UDP retry/acknowledgement, TCP fallback, receiver sessions, test coordination and LAN discovery.
- `Windows`: local adapter discovery, fixed PowerShell inspectors, bounded subprocess output/timeouts and helper IPC.
- `Helper`: local-only, predefined privileged operations, local consent, durable temporary-change journal and verified restoration.
- `App`: MVVM WPF application following the supplied dark UI references.
- `Tests`: executable integration harness using real loopback TCP/UDP sockets, fault injection and report round trips.

No existing VBAN project was edited or incorporated. A future VBAN adapter should reuse its protocol logic only after source review. Third endpoints and AI account connections are intentionally outside this version.

## Protocol and threat boundaries

The operator supplies both literal IPv4 addresses and a random 128-bit shared pairing code. HMAC-SHA256 authenticates the canonical envelope. Version, message ID, request/response type, command, timestamp and payload are signed. A 60-second clock window and a 125-second bounded request cache reject stale traffic and prevent the same request from executing twice across retry/fallback. One shared code is for one pair/session. It is not persisted or logged. Diagnostic content is authenticated but unencrypted.

UDP control sends a request up to three times with 750 ms acknowledgement windows. TCP uses a bounded length-prefixed frame. Both transports enforce source address, authentication and message size. Health probes monitor both paths; UDP is preferred if both pass. The same request ID is retained on fallback. Handlers support ping, peer summary, preparing a bounded receive test, sending bounded test data to the configured peer/port, finishing a test, and the shared check's start/progress/end/cancel messages. There is no remote shell or remote privileged action.

UDP test packets use a separate unpredictable test token, test ID, sequence, timestamp and verified payload. Test limits are 300 records, 1200 bytes, and a six-second sender deadline. Default UDP sends 200 records with a five-millisecond pacing delay. Receive sockets close after ten seconds and use exclusive binding. The receiver result is authoritative for measured delivery; a local successful send is not remote-delivery evidence. TCP verifies application records and acknowledges the whole transfer, without mislabelling transfer duration as packet RTT.

LAN discovery is untrusted and advertises machine/address/control port only. No authenticated action follows until manual peer selection and code pairing. Control and test addresses stay bound to the selected interface. Changing interface requires stopping the endpoint. Automatic alternate-interface rerouting is not implemented.

The UI opens a random, current-user-only named pipe and starts the helper with UAC `runas`. The helper proves possession of a fresh nonce and accepts one validated allowlisted request. Every action gets a local confirmation in the elevated helper. Helper messages cannot request arbitrary commands or executable paths. Remote peer handlers cannot call the helper.

`CreateRestorePoint` uses Windows PowerShell 5.1 `Checkpoint-Computer` with `MODIFY_SETTINGS`, then reads `Get-ComputerRestorePoint`. A successful command exit alone is insufficient: Windows can skip creation under its frequency policy. The unique session name, sequence number and creation time identify the baseline. Creation has a ten-minute subprocess deadline and a fifteen-minute helper deadline. No adapter, peer or configured ports are required for creation or pending-change recovery.

`RestorePoints.RequireFor` runs inside the elevated helper before any QoS trial, adapter restart, cache flush or reset. A receipt in local app data is only a reference: its machine/session identity, age under 24 hours, exact name, sequence and timestamp must match a live Windows query. Failed or missing queries block repair. WFP/PktMon evidence capture and emergency rollback are exempt. A manually created Windows point with the exact session name can be verified as the baseline. The app does not modify the restore frequency registry value or automatically enable protection. UI buttons open the Windows protection/recovery dialogs without applying recovery.

Restore-point tests inject an in-memory backend to cover creation failures, silent skips, deleted/mismatched points, session/machine binding, age limits, resumed sessions and manual creation. Windows PowerShell date/JSON mapping is exercised with a local fixture function; the creation script is parsed without execution. Automated tests never create a real restore point or run a live repair.

## Recovery and storage

`DiagnosticWorkflow` attempts stages 1–7 independently and always produces the stage-8 assessment, including after cancellation. A filtering error does not stop tracing. Packet tracing invokes the existing bounded WFP and PktMon helper actions with their local prompts; cancellation is a distinct IPC terminal message, never a successful capture. No repair action is called by the scan.

`DiagnosticAssessment` contains typed observations from this run and selected address/port scope, not parsed human summaries or imported evidence. It records baseline tests plus capture retests and preserves intermittent failures. Structured port ownership excludes this app's PID and unrelated interfaces/ports. WFP event parsing prohibits DTDs/external entities and bounds document size; only fresh 5152 events with the selected IPv4 pair, TCP/UDP protocol and test source/destination port are matched. Invalid or truncated event data remains inconclusive. Filter IDs are reported for review against the WFP state; PktMon traces are exported rather than claimed to be fully correlated automatically.

The deterministic recommendation rules do not execute commands. They distinguish confirmed port ownership/drop observations from possible conflicts and optional trials. A QoS trial suggestion requires measured UDP failure, successful TCP in both directions, no matching WFP drop or competing listener, and completed captures with readable WFP data. Missing evidence and failed/inconclusive retests prevent broad healthy-network conclusions. Final human-readable recommendations become session evidence and are included in support/export reports.

QoS and packet-drop audit settings are saved before mutation and restored in `finally`, with readback. A remaining journal blocks another privileged operation until recovery is reviewed. Closing the UI does not cancel helper cleanup. Full process/OS termination can interrupt cleanup; the durable record supports the next explicit recovery. PktMon cleanup is bounded and performed in `finally`, but abrupt helper termination may require manual inspection of PktMon status.

Version 0.1.3 fixes the no-auditing round trip: a queried/saved value of zero must be sent to `AuditSetSystemPolicy` as `POLICY_AUDIT_EVENT_NONE` (4), since zero means `UNCHANGED` for the setter. Readback compares effective success/failure bits and accepts both zero and explicit NONE as disabled. Unknown or contradictory flags are rejected. The query/set functions return native one-byte BOOLEAN. Tests model Windows setter semantics and exercise trial/restoration from every supported baseline, write/readback failures and old zero-valued recovery records. The fix consumes existing recovery journals without deleting the safeguard early.

Winsock/IP resets save configuration evidence and a reboot marker. That marker is not a full rollback image. The UI verifies a boot occurred after the marker before acknowledging it. No reset or reboot is silently repeated.

Session evidence is bounded to 500 records / approximately one million characters. Exports include only capture paths referenced by the current session, with per-file and count bounds. Offline ZIP import reads `session.json` without extracting arbitrary archive paths and has an 8 MB entry limit. Imported evidence is labelled as external evidence. New session leaves saved capture files on disk; there is no automatic capture-retention deletion in this version.

## Validation boundary

Build and local tests cover protocol authentication, message validation, retries, duplicate suppression, both transport failovers, bidirectional socket delivery, payload checks, port conflicts, packet counting, offline operation and report persistence. Read-only Windows inspectors are separately exercised. Actual WPF rendering is checked using `--render-preview <absolute-png-path>`.

The following require a supervised target-PC validation pass: UAC/helper IPC, actual Windows restore-point creation and recovery, WFP auditing and restoration, PktMon capture, QoS restoration, NIC restart, system resets and post-reboot continuation; LAN discovery and pairing through Windows Firewall on two physical PCs. These operations were not run against the developer's live network as part of the build.

## Packet path foundation (0.1.4)

`PktmonCapture` retains command output, existing filters, component list, active status, counters before stop, and ETL statistics. Start explicitly selects all components, all packet types and the documented default flags (0x032); this is diagnostic configuration, not a claimed fix for the header-only capture. Text export requests hex bytes. Empty or unrecognized snapshot output and failed conversion terminate IPC as inconclusive. Diagnostics are saved before the terminal message. A failed start never stops an existing capture; an owned capture stops if a callback or counter query throws.

`UdpPacketTrace` supports unfragmented IPv4 UDP in Ethernet, up to two VLAN tags, or IP-only snapshots. It matches ELK1 test GUID and sequence to the address pair, destination port and declared payload size. It recognizes bounded offset-based hex dumps and rejects discontinuous or incomplete logged bytes. Unknown formatting, IPv6, encapsulation and TCP remain uncorrelated. Captured prefixes do not verify the full payload or checksums; the receiving socket separately verifies the Elka payload. Component observations are snapshots, not unique packet counts.

`PacketPath` presents seven checkpoints and a sample sequence's local component observations. PktMon drops are reported by component ID/reason; WFP 5152 events are matched at flow level. Neither automatically attributes a problem to a firewall vendor. Missing observations do not identify a failure location. NIC mapping remains unconfirmed until component metadata supports it. Saved view data is labelled with the scan time; a new scan/session clears it. Exported full-scan evidence contains the readable path report.

Next steps after a populated target-PC capture is available:

1. Verify capture formatting and component schema on supported Windows builds; map component IDs to the selected NIC and drivers using the captured inventory.
2. Add locally approved captures on both endpoints, exchange readiness, then send shared test IDs. Join by ID/sequence: PktMon group IDs and wall clocks alone cannot identify packets across PCs. Keep control/capture failure distinct from packet loss; preserve offline export.
3. Add per-sequence receiver observations and WFP filter ownership. Report missing observations as gaps, never inferred drop locations.
4. Add VBAN identity/payload decoding and its dedicated sender/receiver behind the same evidence model. Verify stream configuration and application processing separately from delivery. Do not bind an occupied VoiceMeeter port or infer audio playback from arrival.

Preview supports `--render-preview <png> 4 --preview-data <fixture-directory>`. Alternate data roots are accepted only in preview mode; synthetic data is visibly labelled and kept separate from the live session.

## Local fault localization and Wireshark integration (0.1.5)

`FaultLocalization` keeps protocol outcomes separate from capture availability and prioritizes explicit matched local drops over a receiver-first investigative suggestion. It never uses configured endpoint roles as proof of health. The packet-path finding selects an existing inspection stage; it cannot execute a repair. Capture-only WFP events produce a directional view with unknown socket counts.

`WfpState` reads bounded netsh XML fragments, including the real two-root wfpstate/firewallState format. It prohibits DTDs and external entities. `PacketEvidence` retains event time, FilterOrigin, LayerRTID and InterfaceIndex. A filter's full configuration and provider/layer context must agree in states surrounding the event (at most five minutes apart); changed, missing or unbracketed IDs cannot acquire ownership. Even matching snapshots are labelled corroboration, not continuous proof of ID stability. Audit restoration completes before the post-window state query. WFP flow events remain separate from ELK1 sequence correlation.

`NpcapCapture` uses installed dumpcap through a predefined elevated helper action, with the adapter GUID, validated literal IPv4 pair, test port, no promiscuous mode, 1600-byte snaplen, 25-second/16-MB/10,000-frame bounds. It owns only its child process and waits for capture-file creation before announcing readiness. Driver errors and stderr counts are retained in a separate diagnostics file. TShark decoding runs in the unelevated app, disables name resolution, bounds listing output to 2 MB and 2,000 frames, and keeps raw captures under 100 MB. A packet's full text/hex view is another bounded read. No remote executable, arbitrary helper command or user-supplied capture filter is accepted.

The full scan independently attempts WFP, PktMon and Npcap through `PacketTracingWorkflow`. Missing Npcap dependencies trigger an explained setup offer even after PktMon fails. A declined/incomplete setup records the reason without discarding completed checks. Detection requires TShark and Dumpcap in one installation plus the Npcap DLLs and driver file; it does not prove driver access. An actual capture verifies that. The standalone packet viewer and external-file reader do not assert internal Windows drop locations. Current captures and companion files are selected for export before the 50-file bound, so older unreferenced files cannot displace them.

Setup is explicitly accepted in the UI. It downloads the pinned official Wireshark 4.6.9 x64 installer, checks its published size/SHA-256 and valid Wireshark Foundation Authenticode signature, then awaits the interactive official installer and rechecks the component files. Starting in 0.1.7, Wireshark/Npcap setup does not create or require a restore point, as requested by the user. The network-repair restore-point guards remain unchanged. Cancelling the wait never kills a driver installer. The PowerShell signature check explicitly imports the Windows PowerShell security module to avoid inheriting an incompatible PowerShell 7 module path. Setup is not silently run at startup. Wireshark/Npcap are not redistributed in the Elka ZIP. Installed tools are found through the machine-wide Wireshark uninstall registration or Program Files, never through PATH, HKCU or peer input.

### PktMon buffer correction (0.1.6)

The old 16 MiB circular-file maximum equalled the ETW buffer size recorded in the user's header-only ETL. A controlled local comparison with unchanged flags, filters and bounded loopback traffic reproduced 3 metadata events at 16 MiB and 8,557 PktMon events at 64 MiB. `PktmonCapture.CaptureFileMegabytes` is now 64. The capture still stops in a finally block and never stops another session after rejected startup. Readiness requires successful `status`. A bounded start/status/counters/stop/statistics summary is sent to the UI and retained in Copy for support; the full transcript remains exportable. Busy circular traces may overwrite older observations; missing matched IDs still cannot establish a drop.

`scripts/verify-pktmon-buffer.ps1` is an explicit development diagnostic, never called by the application. It requires elevation, starts two short captures sequentially, verifies 20 loopback UDP deliveries in each, stops only after successful startup, and saves ETL/text/statistics. It changes no adapter, firewall or audit settings. Raw captures include background traffic and stay in ignored local artifacts.

### Sequential capture reporting (0.1.8)

The later Npcap retests have different test IDs from the earlier PktMon window. `PacketPath.Build` keeps the latest directional results first and also retains earlier scoped UDP tests with matched PktMon snapshots. Their titles and full test IDs distinguish the runs. A latest test without component observations links to the earlier entry instead of implying the scan collected no component evidence. Socket counts and per-packet drops are never transferred between IDs. Scan-wide totals are explicitly labelled; the text report starts with an index of retained test runs. Saved path loading accepts up to 32 entries, including the six produced by a typical full scan with both capture tools.

Regression cases cover successful and incomplete later retests, earlier explicit drops, report-index visibility and exclusion of captured unrelated addresses. The `--write-path-preview` fixture generator also creates a `sequential-captures` subfolder with four latest directional results and two earlier PktMon runs, to verify save/reopen and UI layout without live capture.

Optional validation arguments: `--wireshark-tools <extracted-or-installed-Wireshark-directory>` runs the real offline decoder against a synthetic Elka UDP PCAP; `--inspect-wfp <saved-state.xml>` reads a real saved state; `--download-wireshark-installer <validation-directory>` tests download and integrity checks without launching setup. Those dependencies and fixtures stay under ignored artifacts/test-data, outside the release package. Actual Npcap installation/live capture and both-PC behavior remain supervised validation tasks.

- [Wireshark dumpcap](https://www.wireshark.org/docs/man-pages/dumpcap.html)
- [Wireshark TShark](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Official 4.6.9 release hashes](https://www.wireshark.org/download/SIGNATURES-4.6.9.txt)
- [Npcap redistribution terms](https://npcap.com/oem/)
- [WFP filter origin](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/filter-origin-documentation)

## Shared two-PC checks (0.2.1)

`CoordinatedCheck` wraps the socket RPC handler with authenticated Begin/Update/End/Cancel commands. The initiator performs one four-direction sequence; the participant runs its actual prepare/send/finish socket operations and receives ordered combined observations. Both view models receive the same session ID and progress, switch to Protocols, disable conflicting commands and save their local perspective of the shared results. Participant evidence identifies the paired PC as the source of combined observations. The individual protocol buttons and full local Windows scan retain their existing behavior.

Start and progress RPCs acknowledge promptly; the whole scan is never placed inside an eight-second control request. A capability field defaults to false for older peers; the shared button requests an update instead of silently falling back to an invisible remote check. Session IDs, sequence checks, scoped result validation, bounded completed-session history and the existing RPC duplicate cache prevent stale/duplicate messages from resetting a report. Only one shared check may be active. UI admission rejects a remote start during any other local operation before replacing the assessment.

Either endpoint can cancel. The participant expires after 90 seconds without progress if the initiator disappears. Partial observations are retained and missing directions never become zero-count losses. Control transport failover still applies to progress/result exchange independently of the tested protocol. This protocol exposes no capture, elevation, installer or repair commands; deeper Windows inspections remain locally initiated.

`CoordinatedCheckTests` uses two real loopback addresses and authenticated control listeners. It verifies starting from either endpoint, identical four-direction results, participant-relative projection, live progress, busy and legacy peers, duplicate/stale messages, scope validation, occupied UDP receiver, cancellation on either endpoint, TCP control fallback and participant timeout with retained partial evidence.

## Future assisted workflow

The support summary is the first bridge to AI assistance. A future provider adapter can consume a bounded, user-selected report. Any model-generated advice should be treated as a proposal, display exact affected scope and evidence, and map only to the existing predefined local operations after user approval. Do not add arbitrary model/remote shell execution or silently upload captures. Provider credentials must live in a suitable Windows credential store, not settings, logs or reports.

## Windows references

- [AUDIT_POLICY_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-audit_policy_information): distinguish UNCHANGED (0) from explicit NONE (4) when restoring disabled auditing.
- [Windows event 5152](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5152): match source/destination address, port, protocol and filter run-time ID from event XML.
- [Checkpoint-Computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/checkpoint-computer?view=powershell-5.1): Windows client restore-point creation, restore-point types and frequency limits.
- [CreateRestorePoint](https://learn.microsoft.com/en-us/windows/win32/sr/createrestorepoint-systemrestore): Windows can return success while skipping creation under the frequency limit; require readback.
- [SystemRestore class](https://learn.microsoft.com/en-us/windows/win32/sr/systemrestore): sequence number, description and creation time identify a Windows restore point.
- [Find-NetRoute](https://learn.microsoft.com/en-us/powershell/module/nettcpip/find-netroute): distinguish the route Windows selects from a source-bound test.
- [Get-NetAdapterStatistics](https://learn.microsoft.com/en-us/powershell/module/netadapter/get-netadapterstatistics): errors and discard counters are collected as evidence.
- [netsh wfp](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wfp): export state without deleting filters.
- [Audit Filtering Platform Packet Drop](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-filtering-platform-packet-drop): 5152 packet-drop auditing; 5157 belongs to connection auditing and is not promised by enabling the packet-drop category.
- [Filter-origin audit documentation](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/filter-origin-documentation): correlate a drop's run-time filter ID before attributing a cause.
- [PktMon command formatting](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon-syntax): counters, component IDs, snapshot group/number/appearance and drop reasons.
- [Microsoft PktMon event parser](https://github.com/microsoft/NetMon_Parsers_for_PacketMon/blob/main/etl_Microsoft-Windows-PktMon-Events.npl): snapshot field semantics.
- [Checksum offload](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/offloading-checksum-tasks): checksums can be completed by the NIC; they are not packet identities.
