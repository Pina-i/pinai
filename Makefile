SHELL := bash
.SHELLFLAGS := -c

# Service targets are forwarded to the owning subtree: its recipes resolve
# docker/.env.* and ./keys relative to their own directory.
SERVICE_TARGETS := alice bob alice-seed bob-seed \
                   alice-docker bob-docker alice-docker-win bob-docker-win \
                   alice-down bob-down alice-down-v bob-down-v

.PHONY: $(SERVICE_TARGETS) fmt fmt-check lint check

$(SERVICE_TARGETS):
	$(MAKE) -C identity-provider $@

# ── Workspace-wide (all 21 crates) ───────────────────────────────────────────

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

lint:
	cargo clippy --workspace --all-targets -- -D warnings

check: fmt-check lint
	cargo test --workspace
