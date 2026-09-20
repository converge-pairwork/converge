# Instructions for AI assistants working in this repository

[CONTRIBUTING.md](CONTRIBUTING.md) is the whole of the guidance: read it, and follow the style
section in particular. No dashes as punctuation, and one place knows each rule.

Two things are said here rather than there, because they are about the commit and not about the
change it carries.

# Attribution

Do not add `Co-authored-by`, `Signed-off-by`, or any other attribution, authorship or
provenance trailer naming Claude, Codex, OpenAI, Anthropic, or any other AI tool or model, to a
commit message or to a pull request description. The same goes for a body line or a footer that
says the same thing in prose.

A commit made while assisting this project keeps the configured human Git author and committer
identity. Do not set, override or suggest `GIT_AUTHOR_*`, `GIT_COMMITTER_*`, `--author`, or
`user.name` and `user.email`, unless the owner asks for that in so many words.

`.claude/settings.json` sets `includeCoAuthoredBy` to false, which is what stops Claude Code
adding the trailer by default. Leave it set.

# Published releases

A tag that has been released is immutable, and `v0.1.1` is the one exception to that, made once
and on the owner's instruction. Do not rebase, amend, filter or force-push released history.
That includes removing an attribution trailer: the trailers inside a published tag are not worth
another rewrite.

Be accurate about why. The Ed25519 signature is over the bytes of `manifest.json` and over
nothing else, so rewriting a commit does not break it. What broke was further along: a tag push
starts the release workflow, the workflow rebuilt every artifact over the published release, and
that left a new `manifest.json` beside a signature over the bytes it had replaced. Every
installation refused the release until the owner signed again. `scripts/release-guard.py` now
refuses to let automation write to a published release at all, so that particular way of
breaking one is closed; the rule against rewriting released history stands on its own.

`v0.1.1`'s tag and its signed manifest both name `b3cdac16` again, and
[docs/RELEASE.md](docs/RELEASE.md) section 10 is the account of how they came apart.
