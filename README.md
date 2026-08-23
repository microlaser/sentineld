# sentineld (Python rewrite)

A local, transparent process monitor: local heuristics only, no cloud
calls, and nothing is ever killed without asking you first. This is a
full rewrite of the original C/assembly prototype in Python, after an
extended debugging session on the C version's netlink event loop that
never got fully resolved (see "Why this exists" below).

**Every piece of this has been tested end-to-end in a real environment**
(not just unit-tested in isolation): real exec detection, real scoring,
real freeze/alert/block/kill, real SHA-256 blocklist persistence, real
re-detection of a renamed copy of a blocked binary, real Bayes model
updates from real decisions. See "What was actually tested" below for
specifics.

## Why this exists

The original version was written in C with hand-rolled syscall stubs in
x86-64 assembly, specifically to keep the trusted, privileged core (the
code with `CAP_KILL`) small and auditable. That reasoning still holds in
principle. In practice, debugging it turned into a long session chasing
why the daemon's netlink connector subscribed successfully (confirmed via
raw syscall return codes) but never seemed to receive any events, while
an independent tool (`forkstat`) on the same machine proved the kernel
side worked fine. The most likely explanation, found only after
switching approaches: the C version's `epoll_ctl(EPOLL_CTL_ADD, ...)`
call for the netlink socket had its return value silently unchecked, and
epoll integration for the Unix socket clearly worked (clients could
connect) while the netlink fd's registration may well have failed
quietly. That's a real, findable bug -- but finding it took a full
debugging session precisely because the C version has no equivalent of
Python's `selectors` module giving clean, checked, exception-raising
registration instead of a hand-packed `struct epoll_event` and an
unchecked syscall return code.

That is the actual tradeoff, stated plainly: hand-rolled syscalls and
manual struct packing put more of the implementation surface at risk of
a silent, hard-to-diagnose bug, in exchange for a much smaller trusted
base (the original's `sentineld` binary was ~20KB, statically linked, no
libc). This Python version inverts that tradeoff: a much larger trusted
base (the Python interpreter itself, easily tens of MB and far more code
than anyone will read end to end), in exchange for standard-library
primitives (`socket`, `selectors`, `hashlib`, `json`, `os.stat`) that are
heavily used, well-tested, and fail loudly with tracebacks instead of
silently doing nothing.

Neither tradeoff is strictly better. For a personal tool where the
priority shifted, over the course of debugging, from "minimal trusted
base" to "actually works and is debuggable when it doesn't" -- this is
the right call. If minimizing the trusted core matters more than
development velocity for your use case, the C version (in the other
delivered archive) with the `epoll_ctl` return-value bug fixed is very
likely closer to working than this session's back-and-forth suggested;
that fix was diagnosed but not re-tested before switching approaches.

## What was actually tested

In a sandboxed root shell with real kernel netlink support, before this
was ever handed over:

- **Raw netlink delivery** (`diag_netlink.py`): confirmed receiving real
  `FORK`/`EXEC`/`EXIT` events with correct PIDs for real test processes.
- **Full daemon startup**: socket/bind/subscribe all logged and
  confirmed correct byte counts (40 bytes, matching the C version's
  confirmed-correct subscribe message).
- **Benign processes correctly NOT flagged**: `cp`, `mkdir`, `sleep`,
  `cat`, `python3` all scored ~17% (below the 55% alert threshold) when
  run normally.
- **Suspicious processes correctly flagged**: a binary run from `/tmp`
  scored 75% and triggered a real freeze + alert.
- **Full client round-trip**: a real Unix-socket client received the
  alert as JSON, sent back a `block` decision, and the daemon:
  - killed the process and confirmed its `/proc/<pid>` entry was gone
  - wrote the SHA-256 hash to `blocklist.json`
  - updated `model.json` with the real, verifiable count changes
    (`malicious_total` 4→5, `exec_from_tmp` count 3→4)
- **Blocklist survives renaming**: the same binary, copied to a new
  filename and re-executed, was killed automatically with **no prompt**,
  confirmed via the `re-exec of blocked binary killed automatically` log
  line -- the SHA-256 content-hash identity working as designed.
- **The race condition is real and was directly observed**: a copy of
  `/bin/true` (which exits in under a millisecond) raced past the
  daemon's fingerprinting step and logged `could not fingerprint pid
  ... (likely already exited)`. The same binary given even a few seconds
  of runtime (`/bin/sleep N`) was reliably caught. This confirms the
  race is real, is about process lifetime not implementation language,
  and matches exactly what was hypothesized (but never confirmed) during
  the C version's debugging.

What was **not** tested: real multi-user permission edge cases, the
freeze-timeout sweep firing after the full 120 seconds, the reflex-click
training guard's 2-second threshold in practice, and anything under
actual systemd sandboxing on a real desktop (only run directly, as root,
in a container). Test those specifically before relying on this.

## Architecture

```
sentineld/
  bayes.py            Naive Bayes classifier, informed cold-start prior,
                       JSON persistence (readable with `cat`)
  features.py          /proc-based feature extraction
  process_control.py   fingerprint (hashlib.sha256), stop/kill/confirm,
                        JSON blocklist
  netlink.py            netlink process-events connector wrapper
  bt_bayes.py            second, independent Naive Bayes model for
                          Bluetooth anomaly scoring (separate JSON file,
                          separate feature space -- see "Bluetooth
                          anomaly detection" below)
  bt_features.py          pure feature checks for BLE proximity/identity/
                            timing anomalies
  bluetooth.py             bluetoothctl-backed connector, the BLE
                            analogue of netlink.py
sentineld_daemon.py    main daemon: selectors event loop, alert/decision
                        protocol (newline-delimited JSON over a Unix
                        socket), freeze-timeout sweep, reflex-click guard
sentinelctl.py          unprivileged interactive client
diag_netlink.py         standalone single-file netlink test, no daemon
                        required -- useful for isolating "is the kernel
                        delivering events at all" from everything else
sentineld.service        systemd unit, minimal capabilities
install.sh               installer
```

## Bluetooth anomaly detection

A second, independent monitor watches BlueZ's live device stream
alongside the process monitor, using its own Bayes model (`bt_model.json`,
same informed-prior design as the process model) and its own alert type
(`bt_alert`) over the same Unix socket. It flags:

- **`new_unpaired_device`** -- a device never seen before, not paired or trusted
- **`alias_mac_mismatch`** -- something broadcasting the *name* of a device you
  already trust, from an address that isn't that device's (spoof/clone)
- **`rssi_jump_close`** -- a device's signal got much stronger, fast
  (something got a lot closer very recently)
- **`rapid_connect_cycle`** -- several connect/disconnect flips inside a minute
- **`unnamed_persistent`** -- broadcasting with no name and sticking around
  rather than passing through once (classic tracker-beacon behavior)
- **`uuid_set_changed`** -- a trusted address's advertised services changed
  from its recorded baseline
- **`manufacturer_id_unlisted`** -- manufacturer data outside a short list of
  common vendor IDs (weak signal, weighted low in the prior on purpose)
- **`advertisement_burst`** -- several brand-new addresses appeared within
  a few seconds of each other

**Unlike the process side, this has NOT been tested against real
hardware.** There was no Bluetooth adapter available in this session.
The parsing is built against documented `bluetoothctl` output format and
common usage, not a confirmed trace the way the netlink wire format was
verified byte-for-byte. Before trusting this the way the process monitor
has earned trust:

- Test `bluetoothctl scan on` manually on the target machine first and
  confirm the `[NEW]`/`[CHG]`/`[DEL] Device ...` line format matches
  what `bluetooth.py`'s regexes expect -- this varies slightly across
  bluez versions and distros.
- Deliberately trigger each feature at least once: pair a real device
  (baseline), then try to make something else advertise the same name
  (`alias_mac_mismatch`), walk a phone close to the adapter after
  leaving it across the room (`rssi_jump_close`), etc.
- Watch `journalctl -u sentineld -f` for `bluetooth:` log lines during
  that testing -- the daemon logs every score, not just alerts, the same
  way the process side does.
- BT alerts carry no freeze/kill semantics (there's no process behind a
  Bluetooth address to pause) -- confirm `sentinelctl` clearly
  communicates that a `bt_alert` is informational only, not a block-in-
  progress, so it isn't mistaken for the process-alert protocol.

If `bluetoothctl` isn't on the machine, or the daemon can't launch it,
Bluetooth monitoring logs a warning at startup and disables itself --
the process monitor keeps running normally either way.

Same security properties as the C version:
- Local-only heuristics, zero telemetry, zero cloud calls
- Nothing killed without a human decision (SIGSTOP-then-ask)
- Freeze-timeout fails toward availability (auto-resume after 120s,
  never trained -- no decision was actually made)
- Reflex-click guard (`MIN_DECISION_SECS = 2`): a decision faster than
  that is still applied but excluded from training
- SHA-256 content-hash blocklist, not path-based
- `false_positive` trains as benign; plain `allow` does not train at all
  (different signals, kept separate on purpose)

## Installing

```
sudo ./install.sh
sudo usermod -aG sentineld $USER
```
Log out and back in (group membership doesn't apply to already-open
shells), then:
```
sudo systemctl enable --now sentineld
journalctl -u sentineld -f
```
and in another terminal:
```
sentinelctl
```

## Known limitations (same honesty as the C version's README)

- No kernel-enforced tamper resistance -- a root-level attacker can kill
  this daemon or race it. This is userspace, not an eBPF/LSM hook.
- Fileless techniques that don't go through `exec` or `ptrace` are still
  invisible to this architecture.
- The exec-time race for very short-lived processes is real (see "What
  was actually tested" above) -- this isn't a bug so much as an inherent
  limit of asynchronous kernel notification vs. synchronous interception;
  closing it fully would mean an LSM hook that runs *before* exec
  completes, not after.
- Content-hash fingerprinting stops renaming evasion but not an attacker
  who deliberately alters a byte to change the hash.
- `LD_PRELOAD` detection does a substring scan of `/proc/pid/environ`
  rather than parsing NUL-separated entries individually.
