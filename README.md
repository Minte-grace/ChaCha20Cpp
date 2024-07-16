# ChaCha20 Encryption/Decryption Tool

## Overview

This C++ program implements the ChaCha20 stream cipher, a high-speed encryption algorithm designed by Daniel J. Bernstein. ChaCha20 is widely used for its security and performance, particularly in environments where AES hardware acceleration is unavailable.

## Features

- Implements ChaCha20 encryption and decryption
- Command-line interface for easy use
- Supports 256-bit keys and 64-bit nonces
- Handles arbitrary message lengths

## ChaCha20 Algorithm

ChaCha20 is a stream cipher that operates on 64-byte blocks. It uses a 256-bit key, a 64-bit nonce, and a 64-bit block counter. The algorithm consists of the following main components:

1. **Initial State**: A 4x4 matrix of 32-bit words, initialized with constants, key, counter, and nonce.
2. **Quarter Round**: The core function that mixes four words.
3. **Block Function**: Applies 20 rounds of quarter round operations (10 column rounds and 10 diagonal rounds).
4. **Encryption**: XORs the keystream generated by the block function with the plaintext.

