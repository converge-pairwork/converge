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

A tag that has been released is immutable, and `v0.1.1` is the one exception to that, made
once and on the owner's instruction. Do not rebase, amend, filter or force-push released
history. That includes removing an attribution trailer: the trailers inside a published tag are
not worth another rewrite.

Be accurate about why. The Ed25519 signature is over the bytes of `manifest.json` and over
nothing else, so rewriting a commit does not break it. What a rewrite does is leave the signed
manifest naming a commit that is no longer in the repository, and no part of the install or
update path resolves that field, so nothing fails and nothing says so either. A silent gap in
the provenance record is the cost, not a failed verification.

`v0.1.1`'s manifest names `b03448ac`, which was rewritten to `b3cdac16`.
[docs/RELEASE.md](docs/RELEASE.md) carries the full mapping. Anything that reads the manifest's
`commit` field for that release needs it.
