.PHONY: all bridge test bridge-test host-check platform-test skill-update-test version-check \
        safety-check release-test check dist clean

# The CONVERGE client: one C++ binary and the Python pieces that install, update and render it.
# Nothing here needs a relay, an account or a network: everything below runs offline, against
# scratch directories, and never reads or writes the real ~/.converge.
all: bridge

bridge:
	cmake -S bridge -B bridge/build -DCMAKE_BUILD_TYPE=Release && cmake --build bridge/build -j

# Everything. This is what CI runs on Linux, Windows and macOS alike.
check: test host-check platform-test skill-update-test version-check safety-check release-test

test: bridge-test

# The bridge's own suites: the cryptography, the platform seam, the in-session interaction.
bridge-test: bridge
	ctest --test-dir bridge/build --output-on-failure

# What each host sees when CONVERGE is invoked: banner, version, menu, tool schema. No relay.
host-check: bridge
	python3 scripts/host-check.py

# Portability of the local AI-session pieces: the state-path resolver on each platform, the
# update lock, replacing a file that is in use, paths with spaces and non-ASCII characters, the
# live-acknowledgement path checks, live-hook removal, and proof that tests isolate real state.
platform-test: bridge
	python3 scripts/platform-test.py bridge/build/converge-bridge

# The updater against a throwaway local release: throttle, semver, signatures, integrity,
# atomicity, concurrency and every failure mode. Needs nothing running.
skill-update-test:
	python3 scripts/skill-update-test.py

# VERSION, the packaged skill and the built binary must all state the same thing.
version-check:
	python3 scripts/version-check.py $(wildcard bridge/build/converge-bridge bridge/build/converge-bridge.exe)

# Is this tree safe to publish? Runs over the working tree, not only what is committed.
safety-check:
	python3 scripts/safety-check.py

# The release tooling, against a whole fabricated release: a deterministic manifest, every way
# a release can be incomplete or ambiguous, signatures made and broken, and the proof that the
# workflow cannot sign anything. Needs no key and no network.
release-test:
	python3 scripts/release-test.py

# Assembles a release directory and writes its manifest and SHA256SUMS. It does not publish
# anything: .github/workflows/release.yml is what turns this into a GitHub release.
# COMPLETE=1 builds it the way the release workflow does: every platform or nothing. On one
# machine that will fail, which is correct, and is why it is not the default here.
dist: bridge
	rm -rf dist && mkdir -p dist
	cp bridge/build/converge-bridge dist/converge-bridge-$$(cat VERSION)-$$(scripts/platform-name.sh)
	cp agent/skill.md agent/converge-live.py agent/converge-update.py agent/install.sh dist/
	git archive --format=tar.gz --prefix=converge-$$(cat VERSION)/ -o dist/converge-src.tar.gz HEAD
	python3 scripts/release-manifest.py dist $(if $(COMPLETE),--complete --commit $$(git rev-parse HEAD),)

clean:
	rm -rf bridge/build dist
