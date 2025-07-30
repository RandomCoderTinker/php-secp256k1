# php-secp256k1

[![PHP Version](https://img.shields.io/badge/PHP-8.1%2B-blue.svg)](https://php.net)
![License](https://img.shields.io/badge/License-MIT-green.svg)
[![Version](https://img.shields.io/badge/Version-1.0.0-orange.svg)](https://github.com/RandomCoderTinker/php-secp256k1/releases)

A high-performance PHP extension for **secp256k1 ECDSA cryptography**, compatible with Ethereum's signing model (`r||s||v`), using native C via [`libsecp256k1`](https://github.com/bitcoin-core/secp256k1).

---

## Functions

| Function              | Purpose                                           |
| --------------------- | ------------------------------------------------- |
| `secp256k1_sign()`    | Sign a 32-byte Keccak-256 hash with a private key |
| `secp256k1_verify()`  | Verify a signature using a public key             |
| `secp256k1_recover()` | Recover the public key from a signature + hash    |

---

## Ethereum Signing Format

This extension follows Ethereum’s conventions:

* **Keccak-256** hashing for messages (requires [php-keccak256](https://github.com/RandomCoderTinker/php-keccak256) or another true Keccak256 implementation)
* Signature: `r (32 bytes) + s (32 bytes) + v (1 byte)` → **130-character hex**
* Recovered public key: `X || Y` (64 bytes, uncompressed, no prefix) returned by `secp256k1_recover()`

### Address Derivation

To derive an Ethereum address from the recovered public key (raw X||Y):

```php
$pubKey = secp256k1_recover($hash, $signature);             // 128-char hex
$address = '0x' . substr(keccak_hash(hex2bin($pubKey)), 24); // last 20 bytes
```

> ⚠️ Do **not** prepend `0x04`. The extension already strips the uncompressed prefix.

---

## Installation

### Prerequisites

```bash
sudo apt install php-dev autoconf make gcc libssl-dev
```

### Build & Install

```bash
git clone https://github.com/RandomCoderTinker/php-secp256k1.git
cd php-secp256k1
phpize
./configure
make
sudo make install
```

Enable in `php.ini`:

```ini
extension=secp256k1_php.so
```

Restart your PHP-FPM or web server.

---

## Usage

```php
<?php
$from        = "0xf9cfd35bec5210fcacf441385c83c304b4e1661b";
$message     = "Hello, Ethereum!";
$privateKey  = "206936e40c8ab171383082433898a04c7186bc3b4e9fd8e7167605496b58c58a";
$publicKey   = "0378d8ef4f36d9565f9ad2eecdf10a1576612015a60d4ecf91c3b89c8aebd70f31"; // compressed

// 1. Hash message with Keccak-256 (Ethereum standard)
// keccak_hash() is the - https://github.com/RandomCoderTinker/php-keccak256 extension
$msgHash    = keccak_hash($message, false); // 64-char hex

// 2. Sign the hash
$signature  = secp256k1_sign($msgHash, $privateKey); // 130-char hex

// 3. Recover the public key
$pubkeyHex  = secp256k1_recover($msgHash, $signature); // 128-char hex (X||Y)

// 4. Verify the signature
$isValid    = secp256k1_verify($msgHash, $signature, $publicKey);

// 5. Derive Ethereum address
$ethAddress = '0x' . substr(keccak_hash(hex2bin($pubkeyHex)), 24);

// Output results
printf("Signature:        %s\n", $signature);
printf("RecoveredPub:     %s\n", $pubkeyHex);
printf("Signature valid?:  %s\n", $isValid ? '✔ yes' : '❌ no');
printf("Ethereum address: %s\n", $ethAddress);

// Actual Output:
// Signature:        b993d7fddb142208603213d8491ff770b7938cca8d34b635f94131f564ae7ba8630c4918f81ba5f732038cc80040cd86f5760c88d9d199c2acfd8448c9c8b03c1b
// RecoveredPub:     78d8ef4f36d9565f9ad2eecdf10a1576612015a60d4ecf91c3b89c8aebd70f315eb0129adca62958a87a7ffb746c59c6493fe50b94ae94578696bb6bc299b373
// Signature valid?:  ✔ yes
// Ethereum address: 0xf9cfd35bec5210fcacf441385c83c304b4e1661b

```

---

## Output Format

| Function              | Output Type  | Description                 | Example            |
| --------------------- | ------------ | --------------------------- | ------------------ |
| `secp256k1_sign()`    | 130-char hex | `r(64) + s(64) + v(2)`      | `b9...03c1b`       |
| `secp256k1_verify()`  | `bool`       | `true` or `false`           | `true`             |
| `secp256k1_recover()` | 128-char hex | `X(64) + Y(64)` (no prefix) | `78d8ef...299b373` |

---

## Performance Benchmarks

| Operation | C Extension | KornRunner (PHP)  | Speedup  |
| --------- | ----------- | ----------------- | -------- |
| Sign      | 43.496 ms   | 119.792 s         | \~2,754× |
| Recover   | 64.247 ms   | — (not supported) | —        |
| Verify    | 62.131 ms   | 119.484 s         | \~1,923× |

> Benchmark over **1,000 iterations** on identical hardware, comparing native C extension vs. pure PHP.

---

## Real-world Use Cases

This extension supports ECDSA workflows across Layer 1 (L1) and Layer 2 (L2) stacks, including Ethereum-native formats like **EIP-155** (chain IDs) and **EIP-115** (transaction `v` enhancements):

### Layer 1 (L1)

* **Ethereum-style signature generation** (`eth_sign`, `ecrecover`)
* **EIP-155 / EIP-115**: RLP-encoded transactions with chain ID protection
* **Wallet address recovery** and verification
* **Cross-chain tooling** for bridging and custodial services

### Layer 2 (L2) & Off-Chain

* **Rollup & sidechain signature validation**
* **PoS/PoA validator attestation**
* **Embedded cryptography** for IoT, games, and edge PHP runtimes

---

## License

MIT © [RandomCoderTinker](https://github.com/RandomCoderTinker)

---

Built with ❤️ using PHP 8.1+
