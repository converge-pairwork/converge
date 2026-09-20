# Real-host smoke test

CI builds and tests the CONVERGE client on Linux, Windows and macOS, on machines of each kind.
What it has never done is run CONVERGE **inside a real AI host** on any of them. That is a
person's job, and this is the list.

> **Status: not performed.** Nothing below has been carried out on Windows or macOS. This page
> is the checklist, not a report. When someone runs it, the result belongs in an issue or a
> pull request against this file, saying which host, which operating system and which version.

It takes about fifteen minutes per host and needs a CONVERGE account with usable balance and a
second party to call — a colleague, or a second machine with a second handle.

Conventions below: **[CC]** Claude Code only, **[CX]** Codex only, everything else both.

---

## Before you start

| | |
|---|---|
| Host | Claude Code, or Codex |
| Operating system | the one you are reporting on, with its version |
| CONVERGE version | what `VERSION` says, and what the banner says |
| Account | a handle (`cvh_…`) and usable balance |
| Peer | a second handle you can call, and a person on the other end |

Do all of this with `CONVERGE_HOME` set to a scratch directory if you do not want it touching
your real `~/.converge`. Say in your report whether you did.

---

## 1. Installation

- [ ] **1.1** On Linux or macOS: `curl -fsSL https://converge.pairwork.net/agent/install.sh | sh`
      completes, and prints the path it installed to.
- [ ] **1.2** It printed `-> size and sha256 verified against the release manifest`, not a
      source build. (A source build is a valid outcome on a platform with no published binary;
      say which happened.)
- [ ] **1.3** Once a release key is pinned, it also printed
      `-> release manifest signature verified`.
- [ ] **1.4** On Windows: the `.exe` from the release page runs, and `--help` prints.
- [ ] **1.5** `converge-bridge --help` exits 0 and describes the flags.
- [ ] **1.6** Registering it with the host works, using the command the installer printed:
      `claude mcp add converge -s user -- …` **[CC]**, or the Codex MCP configuration **[CX]**.
- [ ] **1.7** Setup completes: **Get started with converge.pairwork.net** in a session, followed
      through to a saved handle. The skill lands in `~/.claude/skills/converge/SKILL.md` **[CC]**
      or `~/.agents/skills/converge/SKILL.md` **[CX]**.
- [ ] **1.8** The live hook is registered and the host did not refuse it: `~/.claude/settings.json`
      **[CC]**, `~/.codex/hooks.json` **[CX]**. Codex will not run a newly added hook until you
      have reviewed it — do that, and say whether it then ran.
- [ ] **1.9** Any file the setup backed up is still there and still readable.

## 2. Invocation

- [ ] **2.1** `/converge` **[CC]** / `$converge` **[CX]** starts CONVERGE.
- [ ] **2.2** Asking in plain words ("use CONVERGE to talk to cvh_…") also starts it.
- [ ] **2.3** The menu appears, and its options are selectable in this host.

## 3. The banner, exactly once

- [ ] **3.1** The banner appears on the first CONVERGE output of the session.
- [ ] **3.2** It shows the version that is actually running, matching `converge-bridge --version`.
- [ ] **3.3** It does **not** appear again on later exchanges in the same session.
- [ ] **3.4** It appears again after the MCP server is restarted, and only then.

## 4. Respond once

- [ ] **4.1** Start a call and send one message. It reaches the peer.
- [ ] **4.2** Their reply is displayed to you.
- [ ] **4.3** After one reply, control comes back to you: the AI does not keep going.
- [ ] **4.4** Your own next message is the one you wrote, not a summary of it.

## 5. Continue automatically

- [ ] **5.1** Choose to let it run for a bounded number of exchanges.
- [ ] **5.2** It runs for that many and stops. Not more.
- [ ] **5.3** Every exchange in between was displayed, in order, none skipped.
- [ ] **5.4** It stops early if the peer stops, rather than waiting indefinitely with no sign.

## 6. Guide the response

- [ ] **6.1** Steer the next reply in your own words.
- [ ] **6.2** What was sent reflects your steer.
- [ ] **6.3** Your steering text is not sent to the peer verbatim as though it were the message,
      unless that is what you asked for.

## 7. Live display

- [ ] **7.1** With the live hook installed, each exchange appears **as it arrives**, not in a
      block when the turn ends.
- [ ] **7.2** Remove the hook (`--no-live-hook`, or delete it) and repeat: nothing is lost.
      Every exchange still appears, at the end of the turn.
- [ ] **7.3** Nothing is displayed twice across the two modes.
- [ ] **7.4** Long messages, non-ASCII text and emoji render without truncation or mojibake.
      This is the one most likely to differ on Windows: report the terminal you used.

## 8. Interruption

- [ ] **8.1** Ctrl-C, or the host's stop, during an exchange. The host stays usable.
- [ ] **8.2** CONVERGE does not leave the host wedged, and the next prompt works.
- [ ] **8.3** Resuming the session finds the call where it was, or says plainly that it ended.
- [ ] **8.4** Killing the bridge process outright leaves no lock that blocks the next start
      for more than its stale timeout.

## 9. Transcript preservation

- [ ] **9.1** After a call, the transcript is complete: every exchange, in order.
- [ ] **9.2** It survives a host restart (`claude --continue` **[CC]**, `codex resume` **[CX]**).
- [ ] **9.3** An exchange that arrived while the AI was mid-turn is in it, not dropped.
- [ ] **9.4** Nothing in it was fabricated: every line is something that was actually sent or
      received.

## 10. Update and version

- [ ] **10.1** Ask which CONVERGE version you are on. It answers, and it matches the banner.
- [ ] **10.2** "Check for updates now" runs, bypassing the hourly throttle.
- [ ] **10.3** On a current installation it says so, and installs nothing.
- [ ] **10.4** With an older version installed, an update is fetched, verified and installed,
      and the banner then says a new version is waiting while still naming the one running.
- [ ] **10.5** After restarting the MCP server, the banner names the new version.
- [ ] **10.6** With the network unavailable, CONVERGE still starts and still works, and the
      version screen says the check failed rather than hanging.
- [ ] **10.7** **Windows only:** an update that replaces `converge-bridge.exe` while it is
      running succeeds, the running session carries on, and the next start is the new version.
      No `.converge-old` file is left behind after the run after that.

---

## Reporting

Open an issue, or a pull request against this file, with:

- host and version, operating system and version, terminal
- CONVERGE version, and whether it was installed from a release or built from source
- every line above, ticked or not, and what happened for the ones that were not
- for a failure: what you did, what you expected, what happened, and anything the version
  screen or `update.json` said

A "this all worked" is as useful as a bug report, and rarer. See
[CONTRIBUTING.md](../CONTRIBUTING.md).
