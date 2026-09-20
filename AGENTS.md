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

A tag that has been released is immutable. `v0.1.1` and every tag after it is named by a signed
release manifest that carries its commit, so rewriting a commit reachable from a released tag
breaks the signature over it. Do not rebase, amend, filter or force-push released history, for
any reason, including to remove an attribution trailer. An unwanted trailer inside a published
tag stays where it is.
