# sentineld

A local, transparent process monitor for Linux. No cloud calls, no telemetry,
no black-box model. When something looks suspicious, it freezes the process
and asks you — in plain language, with a confidence score you can inspect —
instead of silently killing it or silently phoning home.

Think of it as a lightweight, fully local alternative to the "upload
everything to the vendor's cloud for a neural net to decide" model that
commercial EDR tools use. Every heuristic here is a short, readable rule.
Every score is a Naive Bayes calculation over hand-picked features you can
read in one file. Every model update comes from a decision you personally
made. Nothing leaves the machine, ever.

```
$ sentinelctl
sentinelctl: connected. Waiting for alerts (Ctrl-C to quit)...

=========================================================
 sentineld: a new process needs your decision
=========================================================
 Program : payload
 Path    : /tmp/.hidden/payload
 PID     : 48213  (parent: bash, pid 4102)
 Confidence this is malicious: 92%

 Why it's flagged:
   - It's running from /tmp, a folder meant for temporary files, not programs.
   - It's running from a hidden folder (name starts with a dot).

 The process is paused right now -- it is not running while you decide.

 [b]lock and kill it   [a]llow it to continue   [f]alse positive (learn as safe)
 >
```

## Why this exists

Most endpoint security tools make two choices that trade away user control:
they run detection logic in the cloud (so the vendor sees your process
activity, and detection stops if you're offline), and they auto-remediate
based on a model you can't inspect. `sentineld` inverts both of those
choices. It's meant for people who want real protection against
opportunistic malware on their own machine, understand exactly why
something got flagged, and want the system to get smarter about *their*
environment specifically over time — without a single byte of telemetry.

## How it works

1. Subscribes to the kernel's **process-events connector** (netlink,
   `CN_IDX_PROC`) — event-driven, not polling — and hears about every
   `exec()` and `ptrace()` attach on the system in real time.
2. Extracts a handful of cheap, explainable boolean features for each new
   process: running from `/tmp` or `/dev/shm`, a deleted-but-still-running
   binary, `LD_PRELOAD` injection, fileless execution via `memfd`, a
   document viewer spawning a shell, a process impersonating a system
   binary from the wrong path, ptrace injection into an already-running
   process, and a few others.
3. Scores those features with a **Naive Bayes classifier**, Laplace
   smoothed, seeded with an informed prior (these features were hand-picked
   as suspicious for a reason — the model doesn't start blind) and refined
   from there by your own decisions. The entire model is a JSON file of
   integer counts at `/var/lib/sentineld/model.json`. `cat` it any time.
4. If the score crosses a threshold, the process is **frozen (`SIGSTOP`)**
   before anything else happens, and an alert is sent to any connected
   `sentinelctl` session explaining exactly why.
5. You decide:
   - **block** — `SIGKILL`, confirmed dead by polling `/proc/<pid>` (with
     a PID-reuse guard), the binary's **SHA-256 content hash** added to a
     local blocklist so a renamed copy is caught and killed automatically
     with no further prompting, and the fired features counted as
     malicious evidence.
   - **false positive** — resumed, fired features counted as benign
     evidence, so similar processes score lower next time.
   - **allow (just this once)** — resumed, **not** trained. "Let it run
     this one time" and "this pattern is fine" are different signals and
     are kept separate on purpose — otherwise reflexive dismissals would
     quietly desensitize the model over time.

## Safety properties worth knowing about

- **Freeze-timeout fail-safe.** An alert nobody answers auto-resumes after
  120 seconds rather than leaving a process frozen forever if you're away
  from the keyboard. This is explicitly *not* treated as a decision — it
  isn't trained into the model.
- **Reflex-click guard.** A decision that arrives suspiciously fast
  (under 2 seconds after the alert) is still applied, but excluded from
  training — so a habit of fast dismissals can't quietly erode detection.
- **Content-hash blocklist, not path-based.** Blocking a binary follows
  it if it's renamed or copied elsewhere, closing the trivial evasion a
  path-only blocklist would miss.

## Installing

Requires Python 3.9+ and root to install (the daemon itself runs with a
minimal, explicit capability set — not full root — once started).

```bash
git clone https://github.com/yourusername/sentineld.git
cd sentineld
sudo ./install.sh
sudo usermod -aG sentineld $USER
```

**Log out and back in** (or reboot) before continuing — group membership
does not apply retroactively to shells that are already open, and this is
the single most common source of "permission denied" confusion when
setting this up.

```bash
sudo systemctl enable --now sentineld
sentinelctl
```

## Testing it

A standalone end-to-end test script is included — it needs no manual
multi-terminal setup:

```bash
python3 test_sentineld.py
```

It connects as a client, launches a real test binary from `/tmp` designed
to trigger an alert, waits for it, sends a block decision, and confirms
the process actually died — reporting a clear `PASS` or `FAIL (stage N)`
with specific next steps for whichever stage fails.

## Architecture

```
sentineld/
  bayes.py             Naive Bayes classifier, informed cold-start prior,
                        JSON persistence
  features.py           /proc-based feature extraction
  process_control.py    fingerprint (SHA-256), stop/kill/confirm,
                         JSON blocklist
  netlink.py             netlink process-events connector wrapper
sentineld_daemon.py     main daemon: event loop, alert/decision protocol
                         (newline-delimited JSON over a Unix socket),
                         freeze-timeout sweep, reflex-click guard
sentinelctl.py           unprivileged interactive client
test_sentineld.py        standalone end-to-end test
diag_netlink.py          minimal single-file netlink connectivity check,
                          useful for isolating kernel-level issues from
                          everything else
sentineld.service         systemd unit, minimal capabilities
install.sh                installer
```

The daemon (`sentineld_daemon.py` and the `sentineld/` package) is the
trusted, privileged core — it's the code with `CAP_KILL`. `sentinelctl.py`
is deliberately unprivileged: it can only *ask* the daemon to act by
writing a small JSON message over a Unix socket, and cannot touch a
process directly itself.

## Design notes: why Python, and what changed along the way

An earlier version of this was written in C with hand-rolled x86-64
assembly syscall stubs, specifically to keep the privileged core as small
and auditable as possible (the resulting binary was ~20KB, statically
linked, zero libc). That reasoning is still sound in principle. In
practice, a subtle bug — an unchecked `epoll_ctl()` return value that
silently failed to register the netlink socket for event notification —
took a full debugging session to isolate, precisely because hand-packed
structs and unchecked raw syscalls don't fail loudly the way a
`selectors.register()` call does. This version trades a larger trusted
base (the Python interpreter itself) for standard-library primitives
that are well-tested and raise exceptions instead of doing nothing.
Neither tradeoff is strictly better; it depends what you're optimizing
for. If minimizing the trusted core matters more than development
velocity for your use case, a from-scratch C rewrite with checked
syscalls is a very reasonable next step.

Two other real bugs worth knowing about, since they'll bite anyone
extending this: (1) a **cold-start problem** in the original Bayes
scoring formula meant a fresh model was mathematically incapable of ever
alerting on anything — symmetric zero-count priors made
`P(feature|malicious)` and `P(feature|benign)` identical, so every score
landed at exactly 0.5 regardless of input. Fixed by seeding an informed
prior and only accumulating evidence from features that actually fired
(not "features that didn't fire" too, which let a dozen unremarkable
absent signals numerically swamp the one or two that mattered). (2) The
**exec-time race** is real and inherent to this architecture: a process
that exits in under a millisecond (`/bin/true` being the canonical
example) can finish before the daemon gets around to inspecting it. This
isn't a bug so much as a fundamental limit of asynchronous kernel
notification versus synchronous interception — closing it fully would
require an LSM hook that runs *before* `exec` completes, which is a
meaningfully larger project than a userspace daemon.

## Known limitations

- **No kernel-enforced tamper resistance.** A process running as root can
  kill this daemon or race it — this is a userspace netlink listener, not
  an eBPF/LSM hook with kernel guarantees.
- **Fileless techniques outside `exec`/`ptrace`** (raw
  `process_vm_writev`, certain container-escape paths) are invisible to
  this architecture.
- **Content-hash fingerprinting** stops renaming/copying evasion but not
  an attacker who deliberately alters a byte to change the hash — there's
  no code-signing or provenance layer here.
- **`LD_PRELOAD` detection** does a substring scan of
  `/proc/pid/environ` rather than parsing NUL-separated entries
  individually.
- The exec-time race described above is real; anything that lives even a
  couple of seconds is reliably caught, anything that exits in
  microseconds may not be.

This is a working, tested personal security tool — not a hardened,
audited product. Read the code before trusting it with anything that
matters.

## Contributing

Issues and PRs welcome. If you're extending the feature set in
`features.py`, please also add the plain-language explanation in
`bayes.py`'s `EXPLANATIONS` dict — the whole point of this tool is that
the person being asked can understand *why*, not just *that*.

## License

MIT (see `LICENSE`).
