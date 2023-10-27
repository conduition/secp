.PHONY: check check-* test test-*
check: check-default check-mixed check-secp256k1 check-k256

# Checks the source code with default features enabled.
check-default:
	cargo check

# Checks the source code with all features enabled.
check-mixed:
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


test: test-default test-mixed test-secp256k1 test-k256

test-default:
	cargo test

test-mixed:
	cargo test --all-features

test-secp256k1:
	cargo test --no-default-features --features secp256k1,serde,rand,secp256k1-invert

test-k256:
	cargo test --no-default-features --features k256,serde,rand


.PHONY: docwatch
docwatch:
	watch -n 5 cargo doc --all-features
