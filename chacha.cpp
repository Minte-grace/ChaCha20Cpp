#include <iostream>
#include <vector>
#include <cstring>
#include <cstdint>
#include <sstream>
#include <iomanip>

// ChaCha20 constants
#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d) ( \
    a += b, d ^= a, d = ROTL(d, 16), \
    c += d, b ^= c, b = ROTL(b, 12), \
    a += b, d ^= a, d = ROTL(d, 8), \
    c += d, b ^= c, b = ROTL(b, 7))

class ChaCha20 {
private:
    std::vector<uint32_t> state;

    // Performs a quarter round operation on four 32-bit words
    void quarter_round(int a, int b, int c, int d) {
        QR(state[a], state[b], state[c], state[d]);
    }

    // Generates a 64-byte keystream block
    void chacha20_block(std::vector<uint8_t>& output) {
        std::vector<uint32_t> working_state = state;

        // Perform 20 rounds (10 column rounds and 10 diagonal rounds)
        for (int i = 0; i < 10; i++) {
            quarter_round(0, 4, 8, 12);  // Column round
            quarter_round(1, 5, 9, 13);
            quarter_round(2, 6, 10, 14);
            quarter_round(3, 7, 11, 15);
            quarter_round(0, 5, 10, 15); // Diagonal round
            quarter_round(1, 6, 11, 12);
            quarter_round(2, 7, 8, 13);
            quarter_round(3, 4, 9, 14);
        }

        // Add the original state to the working state
        for (int i = 0; i < 16; i++) {
            working_state[i] += state[i];
        }

        // Convert the state to little-endian bytes
        for (int i = 0; i < 64; i++) {
            output[i] = working_state[i / 4] >> (8 * (i % 4));
        }

        // Increment the block counter
        state[12]++;
        if (state[12] == 0) {
            state[13]++;
        }
    }

public:
    // Constructor: initializes the state with the key and nonce
    ChaCha20(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) {
        state = {
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // ChaCha20 constant
            0, 0, 0, 0, 0, 0, 0, 0, // Will be filled with the key
            0, 0, 0, 0 // Will be filled with block counter and nonce
        };

        // Set up the key (8 words, 32 bytes)
        for (int i = 0; i < 8; i++) {
            state[4 + i] = (key[4*i+3] << 24) | (key[4*i+2] << 16) | (key[4*i+1] << 8) | key[4*i];
        }

        // Set up the nonce (2 words, 8 bytes)
        state[14] = (nonce[3] << 24) | (nonce[2] << 16) | (nonce[1] << 8) | nonce[0];
        state[15] = (nonce[7] << 24) | (nonce[6] << 16) | (nonce[5] << 8) | nonce[4];
    }

    // Encrypts the input data
    void encrypt(std::vector<uint8_t>& data) {
        std::vector<uint8_t> keystream(64);
        for (size_t i = 0; i < data.size(); i += 64) {
            chacha20_block(keystream);
            for (size_t j = 0; j < 64 && i + j < data.size(); j++) {
                data[i + j] ^= keystream[j];
            }
        }
    }

    // Decrypts the input data (same as encrypt for ChaCha20)
    void decrypt(std::vector<uint8_t>& data) {
        encrypt(data);
    }
};

// Utility function to convert hexadecimal string to bytes
std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t) strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Utility function to convert bytes to hexadecimal string
std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

int main(int argc, char* argv[]) {
    // Check if the correct number of arguments is provided
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <encrypt|decrypt> <32-byte-key-hex> <8-byte-nonce-hex> <message>" << std::endl;
        return 1;
    }

    // Parse command line arguments
    std::string mode = argv[1];
    std::string key_hex = argv[2];
    std::string nonce_hex = argv[3];
    std::string message = argv[4];

    // Validate key and nonce lengths
    if (key_hex.length() != 64 || nonce_hex.length() != 16) {
        std::cerr << "Error: Key must be 32 bytes (64 hex chars) and nonce must be 8 bytes (16 hex chars)" << std::endl;
        return 1;
    }

    // Convert key and nonce from hex to bytes
    std::vector<uint8_t> key = hex_to_bytes(key_hex);
    std::vector<uint8_t> nonce = hex_to_bytes(nonce_hex);
    std::vector<uint8_t> data(message.begin(), message.end());

    // Create ChaCha20 cipher object
    ChaCha20 cipher(key, nonce);

    // Perform encryption or decryption based on the mode
    if (mode == "encrypt") {
        std::cout << "Original: " << message << std::endl;
        cipher.encrypt(data);
        std::cout << "Encrypted (hex): " << bytes_to_hex(data) << std::endl;
    } else if (mode == "decrypt") {
        std::vector<uint8_t> encrypted_data = hex_to_bytes(message);
        cipher.decrypt(encrypted_data);
        std::cout << "Decrypted: " << std::string(encrypted_data.begin(), encrypted_data.end()) << std::endl;
    } else {
        std::cerr << "Error: Mode must be either 'encrypt' or 'decrypt'" << std::endl;
        return 1;
    }

    return 0;
}