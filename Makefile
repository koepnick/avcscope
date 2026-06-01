build:
	rustup target add x86_64-unknown-linux-musl
	cargo build --release --target x86_64-unknown-linux-musl

install:
	cp ./target/x86_64-unknown-linux-musl/release/avcscope /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/avcscope

