.PHONY: check check-* test test-*
check: check-secp256k1 check-k256 check-all-features check-default check-mixed

# Checks the source code with default features enabled.
check-default:
	cargo check

# Checks the source code with all features enabled.
check-all-features:
	cargo check --all-features
	cargo check --all-features --tests

# Checks the source code with variations of libsecp256k1 feature sets.
check-secp256k1:
	cargo check --no-default-features --features secp256k1
	cargo check --no-default-features --features secp256k1,serde
	cargo check --no-default-features --features secp256k1,serde,rand
	cargo check --no-default-features --features secp256k1,serde,rand,secp256k1-invert
	cargo check --no-default-features --features secp256k1,serde,rand,secp256k1-invert --tests

# Checks the source code with variations of pure-rust feature sets.
check-k256:
	cargo check --no-default-features --features k256
	cargo check --no-default-features --features k256,serde
	cargo check --no-default-features --features k256,serde,rand
	cargo check --no-default-features --features k256,serde,rand --tests

# Checks the source code with both k256 and secp256k1 features enabled.
check-mixed:
	cargo check --no-default-features --features k256,serde,rand,secp256k1 --tests
	cargo check --no-default-features --features k256,serde,rand,secp256k1,secp256k1-invert --tests


test: test-secp256k1 test-k256 test-mixed

test-secp256k1:
	cargo test --no-default-features --features secp256k1,serde,rand,secp256k1-invert

test-k256:
	cargo test --no-default-features --features k256,serde,rand

test-mixed:
	cargo test --all-features

.PHONY: docwatch
docwatch:
	watch -n 5 cargo doc --all-features
