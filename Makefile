static_x86_64:
	rustup target add x86_64-unknown-linux-musl
	cargo build --release --target x86_64-unknown-linux-musl

static_aarch64:
	rustup target add aarch64-unknown-linux-musl
	cargo build --release --target aarch64-unknown-linux-musl

standard:
	cargo build --release

install:
	cp ./target/x86_64-unknown-linux-musl/release/avcscope /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/avcscope

