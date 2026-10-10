# Verification — 2026-10-10, version 0.2.1

## Public preview artifact

`Elka-Network-Diagnostics-0.2.1-win-x64.zip` is the application download for the first public preview. SHA-256: `B4346787DB7F6F03D4403689EBA5FD81AAD0B3EF36CB93C47392B409272CBB55`; size: 72,966,207 bytes. All 466 executable/library files match the tested 12:00:29 package. The refresh adds user documentation, four original guide illustrations, an offline START-HERE.html and the supplied .NET/Windows Desktop runtime notices. It makes no application behavior change.

The offline HTML guide loaded all four local illustrations with no script errors and no horizontal overflow at 390 pixels. Desktop and mobile renders were visually inspected. Markdown guide links resolve in the portable folder. Public-facing examples use fictional addresses; raw target-PC reports, local test artifacts and private verification backups remain excluded from Git.

## User-supplied full-scan reports and illustrated guide

- The user supplied sequential full-scan support summaries from the two target PCs on October 10: the first scan ran 12:12:15–12:14:09Z and the second 12:17:28–12:19:36Z. Both final assessments report UDP and TCP delivered 200/200 in each direction on test port 47831, WFP evidence collected, PktMon text examined to the end, Npcap decoded and no network reset justified. These are user-provided observations, not a new administrator run by this agent.
- First PC: 39,516 readable PktMon snapshot records, 638 matched UDP snapshots retained, 899 Npcap frames decoded. Second PC: 119,058 readable snapshot records, 476 matched UDP snapshots retained, 931 Npcap frames decoded. Both PktMon transcripts report zero lost events. Snapshot counts can include multiple observations of one packet. Background component drop counters are not attributed to the successful test flows. Neither final assessment reports pending audit cleanup or missing capture evidence.
- This provides target-PC evidence for the tested traffic and both local capture workflows. The bounded support summaries do not establish complete NIC-to-socket mapping, VBAN audio delivery, or the shared quick-check UI transition on both screens.
- Rewrote README for end users and added SETUP.md with matching control labels, pairing examples, one-click shared checks, sequential local full scans, waiting for prompts/completion, report export and guided repairs. Added four original, labelled illustrations using fictional example addresses. Visually inspected each PNG; Markdown paths resolve. Packaging now includes the guides, plain-text launch instructions and the PNG assets.
- Documentation-only portable package: `artifacts/Elka-Network-Diagnostics-0.2.1-win-x64-20261010-122316-illustrated-guide.zip`; 72,976,145 bytes; SHA-256 `C59F105872258BA5AB6B700EE58F3CFDB5DBC75B1384ECFED8D5D113AAB2B795`. All 466 executable/library files match the previously tested 12:00:29 package. Application source and behavior were not changed in this documentation pass. No functional test rerun was needed; packaging script syntax, guide paths and formatting were checked. No GitHub repository or public release was created.

## Application verification

- Check both PCs now starts a shared session on both applications. Each screen opens Protocols, displays ordered progress and receives the combined UDP/TCP results for all four directions. The participant saves the results and recommendations from its own local-address perspective, with the shared check ID and peer provenance in evidence. Both endpoints must advertise the new capability; older versions receive clear update guidance.
- Busy endpoints reject a new session before replacing their displayed assessment. Duplicate starts/results/end messages are idempotent; stale IDs, out-of-order results, foreign flows and premature successful completion are rejected. Cancellation works from either PC and preserves partial results. A waiting participant releases its session after 90 seconds without progress. Cancellation also attempts bounded remote receiver cleanup so a retry does not collide with the previous check's listener.
- Final Release build: zero warnings/errors. All **295 checks passed** (`artifacts/verification-0.2.1.txt`). New integration coverage uses authenticated peers on two loopback IPs with actual UDP/TCP transfers, starts from both endpoints, compares complete shared observations, tests participant-relative rows, occupied receive port, busy/legacy peers, duplicate/stale/scoped messages, cancellation from either side, immediate receiver-port reuse, TCP control fallback and timeout with retained partial results.
- No live network settings, elevated captures, repairs or driver installations were changed during development. Initial release validation used loopback integration; the subsequent user-supplied LAN results are recorded above. Full Windows/admin scans remain locally initiated. The new shared protocol exposes no remote administrative commands.

## Tested application package — 0.2.1, before the guide refresh

`artifacts/Elka-Network-Diagnostics-0.2.1-win-x64-20261010-120029.zip`

SHA-256: `60D3C4C00FD6864DEA07C904A2848BF256DE2D64EA62BC816584038A6FDD5A72`

Size: 72,513,404 bytes. Nine main/helper executable, Core/Network/Windows library and guide ZIP entries matched the published folder by SHA-256. The final packaged app rendered and was visually inspected with isolated synthetic two-PC results (`artifacts/packaged-0.2.1-two-pc-pass.png`). This confirms the packaged Protocols layout; the preview does not exercise live remote UI coordination. `git diff --check` passed. Earlier packages are preserved.

## Prior verification — version 0.2.0

- Removed the reference/diagnostic role selector. Both PCs use the neutral `Endpoint` label; persisted and wire role fields remain compatible with older data. No test behavior or fault attribution depends on the label. Existing connection settings remain usable.
- Added Check both PCs: control probing, then UDP and TCP in each direction without privileged operations. The Protocols view shows four rows with separate send/receive counts and results. Full scans publish the initial two-PC assessment after stage 3 and continue the existing local inspections. Starting the scan on the other PC collects that PC's deeper evidence; this update does not introduce remote administration or remote capture approval.
- Test coordination now retains known send results when retrieving receiver results fails. Receiver preparation errors, control failures, actual delivery shortfalls, incomplete sends and acknowledgement errors remain distinct. A successful receiver result with a completion error is not reported as a blocked receiving socket. Failures in both directions do not prove both PCs are faulty; successful retests do not erase earlier failures.
- Final Release build: zero warnings/errors. All 270 checks passed (`artifacts/verification-0.2.0.txt`). Real loopback tests used identical neutral labels on both endpoints and started both protocols/directions from each endpoint. Fault injection covers an occupied remote receive port, missing receiver result after 200 accepted sends, and unavailable control transports. Projection tests cover one-way/both-way loss, mixed outcomes, send errors, acknowledgement errors, unrelated traffic, saved rows and older reports without the new fields.
- No live network settings, capture sessions, repair operations or driver installations were changed. The new UI/command flow still needs a run on the user's physical pair. The exact Windows layer of a drop still requires matching capture evidence; automatic NIC mapping remains unfinished.

## Prior portable artifact — 0.2.0

`artifacts/Elka-Network-Diagnostics-0.2.0-win-x64-20261010-112852.zip`

SHA-256: `457A09097FC6CAD8A1B476C0BF5593E951FC8AF875562EC3127E83A134D158E9`

Size: 72,501,565 bytes. Nine main/helper executable, Core/Network/Windows library and guide entries matched the published folder by SHA-256. Packaged previews were rendered and visually inspected for passing and one-way-failure two-PC tables and the Diagnostics screen (`artifacts/packaged-0.2.0-two-pc-pass-1.png`, `artifacts/packaged-0.2.0-two-pc-shortfall-1.png`, `artifacts/packaged-0.2.0-two-pc-shortfall-0.png`). All four directional rows are visible at the default size; failure results are highlighted separately. `git diff --check` passed. Earlier packages are preserved.

## Prior verification — version 0.1.9

- The user's 10:26–10:28Z report confirms successful UDP/TCP delivery and populated PktMon/Npcap captures on the first test PC. It exposed partial text analysis: 89,236 snapshot headers examined, 1,343 matched UDP snapshots, and an explicit analysis-limit warning that was absent from final recommendations. Capture reported no lost events. These are target-PC observations from the supplied report, not new local captures.
- Both text readers now stream up to 512 Mi characters with fixed buffers and bounded lines. Correlation runs off the UI thread and supports cancellation after capture has stopped. Retained snapshot capacity no longer stops later analysis; later explicit matched drops replace ordinary retained details. Any omission, unread text or cancelled/failed read stays visible in recommendations and the saved overview. Incomplete analysis prevents optional QoS-trial suggestions without changing successful socket outcomes.
- Release build: zero warnings/errors. All 247 available regression checks passed (`artifacts/verification-0.1.9.txt`). New coverage includes a matched packet after 133,000 background snapshots exceeding the former 64-Mi-character limit, header inspection beyond that limit, exact-limit EOF, oversized lines, cancellation, truncated hex, late drops after retention fills, scoped recommendations, and ZIP inclusion of expanded text above 100 MiB with explicit omission manifests.
- The previously extracted TShark and saved live PktMon validation files are no longer present in this workspace. The initial optional-tool run stopped because TShark was missing; the final run used the available suite, including decoder/capture fixtures. No fresh real TShark execution, live two-PC scan, elevated capture, driver installation or network-setting change was performed in this pass. The user's exact raw ETL/text has not been supplied, so its complete analysis still needs a target-PC rerun.
- Automatic NIC/component-name mapping and per-packet Npcap correlation remain unimplemented. Reaching EOF in exported text does not prove that every Windows layer or payload was observable. Wireshark/Npcap setup remains exempt from restore points; network-repair guards remain in place.

## Prior portable artifact — 0.1.9

`artifacts/Elka-Network-Diagnostics-0.1.9-win-x64-20261010-104550.zip`

SHA-256: `E419C64587B97C45788A58C461CDB10E3D0E7C78A10E6A06532AE0E45C0938AC`

Size: 72,493,056 bytes. Eight application/helper executable/library/guide ZIP entries matched the published folder by SHA-256. The packaged app launched in isolated preview mode and displayed the synthetic successful-socket/partial-analysis report on Packet path and Diagnostics. Both previews were visually checked (`artifacts/packaged-0.1.9-partial-4.png` and `artifacts/packaged-0.1.9-partial-0.png`). `git diff --check` passed apart from line-ending normalization notices. Earlier releases are preserved.

## Prior verification — version 0.1.8

- A user-provided support report from the first test PC confirms Wireshark 4.6.9 installer exit 0, component detection, live Npcap capture and 910 frames decoded inside Elka at 10:15:55Z. PktMon had 78,364 readable snapshots, with 1,083 matched to the earlier UDP tests. UDP and TCP completed 200/200 in both directions. These are the user's target-PC results, not captures performed during this development pass.
- That report exposed a presentation gap: later Npcap tests received new IDs and replaced earlier PktMon tests in the path selector. Version 0.1.8 retains earlier captured UDP runs as separate entries, labels scan-wide totals, and indexes retained IDs at the start of the report. Latest incomplete/failed results do not inherit prior successes or packet observations. Reopening a six-entry full-scan report is supported.
- Release build: zero warnings/errors. All 234 checks passed, including six new sequential-capture regression checks and the real offline TShark decoder (`artifacts/verification-0.1.8.txt`). Synthetic six-entry UI data is in `artifacts/packet-path-preview-0.1.8/sequential-captures`.
- Wireshark/Npcap setup remains exempt from restore-point creation. Network-repair guards remain in place. No Windows configuration changes or live captures were performed during this pass. Automatic NIC/component-name mapping and per-packet Npcap correlation remain unimplemented; successful capture must not be presented as continuous NIC-to-socket tracking.

## Prior portable artifact — 0.1.8

`artifacts/Elka-Network-Diagnostics-0.1.8-win-x64-20261010-102156.zip`

SHA-256: `CD6441009318E2288567C035F1F242B4BCD28947C16520B522F118D89E1750E1`

Size: 72,488,596 bytes. Eight application/helper executable/library/guide files in the ZIP matched the published folder by SHA-256. The packaged app reopened six-entry synthetic reports and rendered both the latest-test guidance and earlier PktMon observations. The previews were visually checked: `artifacts/packaged-0.1.8-sequential-captures.png` and `artifacts/packaged-0.1.8-captured-first.png`. Older releases are preserved.

## Prior verification — version 0.1.7

- User explicitly exempted Wireshark/Npcap installation from restore-point creation. Removed the shared setup flow's `CreateRestorePoint` helper call and updated its explanation and user/developer guides. Both the Packet viewer setup button and full-scan setup use this flow. Existing network-repair restore-point guards are unchanged.
- Release build: zero warnings/errors. All 228 regression checks passed, including network repair restore-point guards, capture setup continuation/cancellation, and the real offline TShark decoder (`artifacts/verification-0.1.7.txt`). No new mirror-of-implementation tests were added for this small change.
- No driver installation, Windows restore-point creation, capture or network-setting change was performed during this pass. Interactive installation remains to be completed on the target PC.

## Prior portable artifact — 0.1.7

`artifacts/Elka-Network-Diagnostics-0.1.7-win-x64-20261010-100800.zip`

SHA-256: `E3574BC096F1ACF0337A3B2BBAB67F2D6BD585DB7AE6EC62C5FD1038E44D0C6E`

Size: 72,487,097 bytes. Eight application/helper executable/library/guide files in the ZIP matched the published folder by SHA-256. The packaged app launched and rendered Packet viewer in isolated preview mode (`artifacts/packaged-0.1.7-5.png`). Older releases are preserved.

## Prior verification — version 0.1.6

- Reproduced the empty PktMon trace on this Windows PC with the old 16 MiB circular maximum: 3 metadata events, zero PktMon events, despite increasing packet counters and 20 verified loopback UDP deliveries. Repeating with the same flags and 64 MiB produced 8,560 total events, of which 8,557 were PktMon events. The application text parser recognized all 8,557 packet snapshots. These are observations at components, not unique-packet counts or proof of the second PC's capture result.
- Local A/B capture evidence is in ignored `artifacts/pktmon-buffer-verification/`: `buffer-verification.txt`, `buffer-16.etl/.txt`, and `buffer-64.etl/.txt`. Both sessions were stopped successfully. No adapter, firewall, audit-policy or reset settings were changed. Background traffic is present in the raw captures and is not bundled in the portable release.
- Raised PktMon's circular limit to 64 MiB, required successful status before readiness, and exposed bounded status/counters/stop/ETL-statistics output in Copy for support. Capture cleanup, rejected-start ownership and empty/failed conversion outcomes remain explicit.
- Fixed the scan's silent missing-tools skip. The independent Npcap step now offers setup after WFP/PktMon, waits for the official installer, checks required components again and continues only when they are detected. Decline, cancellation, missing components and setup errors remain visible. Cancelling a wait never kills an active driver installer. Machine-wide registered custom Wireshark paths are recognized alongside Program Files.
- 229 regression checks passed, including failed-PktMon-to-Npcap setup, declined setup, cancellation before capture, missing driver/executables, parser bounds and existing networking/recovery tests. Real extracted TShark decoded the PCAP fixture and returned frame detail; the saved WFP fragment still parsed 232 filters. Log: `artifacts/verification-0.1.6.txt`.
- Actual Wireshark/Npcap installation and live Npcap driver capture were not performed during this pass. Their installer/UAC/reboot interactions and the updated full scan still require confirmation on the user's two target PCs. The local live PktMon comparison validates the buffer correction; it does not establish continuous NIC-to-socket tracking or a fix for an unrelated network fault.

## Prior portable artifact — 0.1.6

`artifacts/Elka-Network-Diagnostics-0.1.6-win-x64-20261010-094141.zip`

SHA-256: `87669B9002E0F80CF419A516DA7AFCB10B40136A1412547B7225AD80D0E84F43`

Size: 72,487,210 bytes. Release build had zero warnings/errors; app and helper publish completed. Eight application/helper executable/library/guide files in the ZIP matched the published folder by SHA-256. No Wireshark/Npcap binaries or live captures are bundled. The packaged application rendered Diagnostics and Packet viewer successfully in isolated fixture preview mode (`artifacts/packaged-0.1.6-0.png` and `artifacts/packaged-0.1.6-5.png`). Existing releases were preserved.

## Prior verification — version 0.1.5

- Final regression run: 217 checks passed, including real loopback UDP/TCP behavior, local fault localization, WFP event metadata and before/after identity checks, Npcap filter bounds and failure handling, packet-list parsing and current-capture export. Release build had zero warnings and errors.
- The real saved WFP state from 01:10:01 parsed as a multi-root XML fragment, yielding 232 filters. No packet-drop event or culprit was fabricated from the filter inventory. State mapping tests reject changed IDs/configuration, mismatched layers, old/unbracketed events and XML entities.
- The official Wireshark 4.6.9 MSI was downloaded, its published hash and valid Wireshark Foundation signature verified, and its tools extracted into ignored validation artifacts using an administrative image. No product or capture driver was installed. Real TShark decoded a synthetic Elka UDP PCAP into two packet rows and returned the selected frame's headers and hex bytes. An invalid capture correctly failed.
- The application's setup downloader separately downloaded the official x64 EXE and passed its published size/SHA-256 and Authenticode publisher checks. The installer was not launched. A nonmatching file was rejected. An inherited PowerShell 7 module-path conflict was found and fixed by importing the Windows PowerShell signature module by its full built-in path.
- UI previews cover the general Diagnostics view, local finding/path view and packet viewer. Fixtures are isolated and visibly synthetic; they are not live drop evidence. The general overview keeps successful traffic delivery separate from incomplete capture. A local WFP/component rejection selects a suggested inspection; no recommendation executes repairs.
- WFP/PktMon capture remain local to the initiating PC. Npcap adds a selected-adapter packet view, not continuous NIC-to-socket tracking. Component-name/NIC mapping, synchronized capture on both PCs, TCP stream matching, VBAN decoding and automatic application-playback verification remain outstanding.
- Actual restore-point/setup/UAC interaction, Npcap driver installation, live capture readiness and counts, and the complete workflow on two physical PCs require supervised validation. No live capture, driver installation, audit-policy change, network reset or firewall change was performed in this development pass. Existing portable releases were preserved.

## Prior portable artifact — 0.1.5

`artifacts/Elka-Network-Diagnostics-0.1.5-win-x64-20261010-085454.zip`

SHA-256: `0209CCFE7D8CCC0A04DAE2991807275DEC41CF93592A22360731F995A18CCB5D`

Size: 72,481,164 bytes. Eight main/helper executable/library/guide files in the ZIP were hash-compared with the published folder. No Wireshark/Npcap binaries are bundled. The packaged app rendered Diagnostics, Packet path and Packet viewer with exit code 0; images are `artifacts/packaged-0.1.5-0.png`, `artifacts/packaged-0.1.5-4.png` and `artifacts/packaged-0.1.5-5.png`. A final read-only check confirmed the standard Wireshark tools and Npcap library remain uninstalled on the development PC.

## Prior verification — version 0.1.4

- Live user-run session evidence confirmed WFP recovery at 01:09:40, a new WFP capture and successful cleanup at 01:10:27, and PktMon start/stop at 01:10:29–01:10:55. The original pending recovery file was absent. Both TCP and UDP passed in both directions. These were the user's live tests; this development turn did not change network settings or audit policy.
- Read-only inspection of the saved PktMon ETL reported three events, all WMI trace metadata and zero manifest/WPP events. Its text contained only a header and two partition records. The new validator correctly reports zero packet snapshots. The cause of the empty capture remains unverified; new status/counters/component/command diagnostics are intended to investigate it.
- 178 checks passed, covering the prior foundation plus empty capture detection, cleanup after failures, preservation of another capture after rejected startup, conversion failures, packet identity/sequence/address/port/size matching, VLAN and IP-only frames, truncation/fragmentation/malformed data rejection, supported hex layouts, explicit drop attribution and checkpoint evidence boundaries.
- Packet path correlation was tested with synthetic PktMon text and real ELK1 payload generation. A populated target-PC capture has not yet validated this parser against that Windows build's hex formatting. Unsupported formats stay unobserved. NIC mapping, synchronized two-PC capture, TCP stream correlation and VBAN decoding are not implemented.
- Release build: zero warnings and errors. UI rendering uses an isolated, visibly labelled synthetic fixture. No live repair or capture was launched during development.
- Final self-contained package launched successfully in preview mode. Upper and lower Packet path content were rendered and reviewed; the direction selector and text wrapping were corrected. The ZIP's main/helper executables, application and shared libraries, and startup guide matched the published files by SHA-256.

## Prior portable artifact — 0.1.4

`artifacts/Elka-Network-Diagnostics-0.1.4-win-x64-20261010-012857.zip`

SHA-256: `D00A1A781A1532C6CD1446EFA9395BD5A78B27866FBFF3209C3E0C8E0DE61206`

Preview images: `artifacts/packet-path-packaged-0.1.4-top.png` and `artifacts/packet-path-packaged-0.1.4-bottom.png`. Preview data is synthetic; it is not evidence of real NIC observations or drops.

## Prior verification — version 0.1.3

- User-provided report and local session evidence identified the first failure at 00:44:58 UTC: WFP captured events, then restoring the original zero-valued audit flags failed readback. The saved WfpAudit recovery record subsequently blocked PktMon before startup. Earlier recorded TCP and UDP tests passed both directions on test port 47831; those are existing user-run results, not development-run capture validation.
- Fixed disabled-auditing restoration by translating saved/query zero to the setter's explicit NONE (4). Compared effective readback states, preserved mismatch/denial failure handling, and declared native BOOLEAN returns correctly.
- 123 automated checks passed, including 19 new audit restoration, pending-action guidance and standalone-trace scope checks. The audit tests simulate the documented API setter semantics; they do not change live Windows audit policy.
- Release build had zero warnings and errors; final self-contained publish succeeded. Packaged application launched and rendered the visible pending-cleanup panel. Executables, Core/Windows libraries and the user guide in the ZIP matched the published files by SHA-256.
- The actual pending recovery record was preserved unchanged. Its restoration and a subsequent live capture remain user-run validation through the corrected helper. A read-only auditpol query was denied due to missing privilege; no claim is made about current live policy readback.

## Prior portable artifact — 0.1.3

`artifacts/Elka-Network-Diagnostics-0.1.3-win-x64-20261010-005143.zip`

SHA-256:

```text
E5057E63422CC9CDCAE932133F99163374D139563376989E3F4DE0FEF28630A9
```

## Full-scan milestone — version 0.1.2

- Final Release build: zero warnings and errors; self-contained app/helper publish succeeded.
- 104 checks passed, covering existing socket/persistence behavior, restore-point guards, complete stage ordering, continuation after filtering errors, cancellation with a partial report, recommendations and WFP event parsing.
- Recommendation checks cover incomplete/declined evidence, both directions/protocols, optional QoS prerequisites, competing/own/unrelated listeners, earlier failures followed by passing retests, and wrong-flow exclusion.
- WFP checks cover the selected pair, protocol, port, time and filter ID; reverse and IPv4-mapped addresses; malformed, missing and external-entity XML. No live packet capture was started.
- The new structured port collector identified actual TCP and UDP sockets owned by the test process through read-only Windows inspection.
- Updated Diagnostics and Admin tools screens rendered successfully and were visually reviewed. The published 0.1.2 executable also launched successfully in preview mode.
- ZIP main/helper binaries, Core/Windows/Network libraries and startup guides were hash-compared with the published folder. Earlier portable archives were preserved.
- Actual elevated captures, restore-point creation/recovery and real two-PC full scans still require deliberate target-PC validation. No live repairs were performed. PktMon ETL/text interpretation and WFP filter ownership are review steps, not automatically proven root causes.

### Version 0.1.2 artifact

`artifacts/Elka-Network-Diagnostics-0.1.2-win-x64-20261010-003110.zip`

SHA-256:

```text
943AF81D4E8C78D957488DAD736FCF6E2974AD62FA1F8C9A7B9E6D580DF28111
```

## Restore-point milestone — version 0.1.1

- Release solution build: zero warnings and errors. Self-contained app/helper publish succeeded.
- 72 automated checks passed: the existing 41 protocol/persistence checks and 31 restore-point checks.
- Restore-point coverage includes denied/disabled creation, Windows silently skipping creation, new-point readback, point deletion, changed identity, another machine/session, 24-hour expiry, clock rollback, corrupt receipts, restart persistence and explicit manual creation fallback. Windows PowerShell 5.1 date/JSON mapping and creation-script parsing were checked without creating a point.
- The restore gate is called inside the elevated helper before repair operations or their recovery journals. UI disablement is supplementary. Evidence capture and pending-change restoration are exempt.
- Both the build output and the packaged executable rendered the new Admin tools screen successfully. The screen was visually inspected, including the first-step restore button and Windows recovery links.
- The new ZIP's main/helper executables, application/Windows/Core DLLs and both startup guides were hash-compared with the published folder. The 0.1.0 portable archive was preserved.
- No live restore point, System Restore recovery or network repair was executed. Actual Windows/UAC creation and recovery still require a deliberate local validation. Simulated restore tests do not establish that recovery succeeds on a target PC.

### Version 0.1.1 artifact

`artifacts/Elka-Network-Diagnostics-0.1.1-win-x64-20261010-002125.zip`

SHA-256:

```text
87B2BDFE81E314F9E520D2D385C75D31885314AB9A3EBCC7BCA5CBF88AB6C4B4
```

Launch `Elka.NetworkDiagnostics.exe` in the extracted folder. A standalone helper launch now explains which executable to open.

## Previous verification — 2026-10-09

This is a testable foundation build, version 0.1.0, not a claim that the original UDP fault has been repaired.

- Release solution build: zero warnings, zero errors.
- 41 protocol/persistence checks passed in the final regression run.
- 12 additional checks passed against the real, read-only Windows network, port, driver/binding and firewall inspectors. All four inspectors returned completed information after fixing .NET/PowerShell adapter GUID matching.
- Both TCP and UDP were tested in both directions using real loopback sockets.
- Injected UDP-control failure selected TCP; injected TCP-control failure selected UDP. Test traffic remained independent of the failed control transport. Loss of both control paths retained local evidence/report operation.
- Retry/fallback duplicate suppression, wrong-code/tampered/stale messages, invalid packet tokens, duplicates/out-of-order packets, occupied test ports, bounded test requests and offline report round trips were checked.
- Packaged WPF app launched in preview mode and rendered Diagnostics, Protocols, Admin tools and VBAN tabs successfully. The actual rendered images were visually inspected.
- Portable package includes .NET Core and Windows Desktop runtimes 8.0.31 for Windows x64. Main/helper binaries and runtime files in the ZIP were hash-compared with the packaged folder.

## Portable artifact

`artifacts/Elka-Network-Diagnostics-0.1.0-win-x64-20261009-100643.zip`

SHA-256:

```text
E7417F08749686A4C1E3597E6F5F0007F5F2C14EE4EDB1AECC91056011862213
```

## Required target-PC validation

Two physical-PC pairing/discovery and asymmetric network behaviour remain unverified. UAC/helper IPC, WFP audit restoration, PktMon, temporary QoS, adapter restart, Winsock/IP reset and post-reboot recovery were implemented but not exercised against the live network. Run these only as deliberate local tests with the original configuration available. No live network repair was performed during development.

VBAN integration, automated capture-to-socket correlation, alternate-interface automatic selection, connected AI assistance, relays and Android support remain outside this foundation. The UI describes VBAN as future integration. Support-summary export is available for manual AI/support use now.
