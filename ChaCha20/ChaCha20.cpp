#include <iostream>
#include <vector>
#include <string>

// https://datatracker.ietf.org/doc/html/rfc8439

typedef unsigned int uint32;
typedef unsigned char uint8;

std::vector<uint8> str_to_uint8(std::string text)
{
    std::vector<uint8> vec(text.begin(), text.end());
    return vec;
}

// bitwise left-rotating
uint32 ROTL(uint32 x, int n) {
    return (x << n) | (x >> (32 - n));
}

// little <-> big endian
std::vector<uint8> serialize(std::vector<uint32> arr)
{
    std::vector<uint8> serialized_state = {};
    for (int i = 0; i < arr.size(); i++)
    {
        uint32 num = arr[i];
        uint8 b0 = (num & 0x000000ff);
        uint8 b1 = (num & 0x0000ff00) >> 8u;
        uint8 b2 = (num & 0x00ff0000) >> 16u;
        uint8 b3 = (num & 0xff000000) >> 24u;

        serialized_state.push_back(b0);
        serialized_state.push_back(b1);
        serialized_state.push_back(b2);
        serialized_state.push_back(b3);
    }

    return serialized_state;
}
std::vector<uint32> serialize(std::vector<uint8> arr)
{
    std::vector<uint32> new_arr = {};
    uint32 res = 0;
    for (int i = 0; i < (arr.size() - (arr.size() % 4)) + 4; i++)
    {
        uint32 num = !(i < arr.size()) ? 0 : arr[i];

        if (i % 4 == 0)
            res |= num;
        if (i % 4 == 1)
            res |= num << 8;
        if (i % 4 == 2)
            res |= num << 16;
        if (i % 4 == 3)
        {
            res |= num << 24;
            new_arr.push_back(res);
            res = 0;
        }
    }

    return new_arr;
}

std::vector<uint32> to32bit(std::vector<uint8> arr)
{
    std::vector<uint32> new_arr = {};
    for (int i = 0; i < arr.size(); i += 4)
    {
        uint32 res = (arr[i] << 24) | (arr[i + 1] << 16) | (arr[i + 2] << 8) | arr[i + 3];
        new_arr.push_back(res);
    }

    return new_arr;
}

// 2.1.  The ChaCha Quarter Round
void QuarterRound(uint32& a, uint32& b, uint32& c, uint32& d)
{
    a = a + b; d = d ^ a; d = ROTL(d, 16);
    c = c + d; b = b ^ c; b = ROTL(b, 12);
    a = a + b; d = d ^ a; d = ROTL(d, 8);
    c = c + d; b = b ^ c; b = ROTL(b, 7);
}

// 2.2.  A Quarter Round on the ChaCha State
void QuarterRoundState(std::vector<uint32>& state, char x, char y, char z, char w)
{
    QuarterRound(state[x], state[y], state[z], state[w]);
}

// 2.3.  The ChaCha20 Block Function
/*
    A 256-bit key   8 32-bit
    A 96-bit nonce  3 32-bit
    A 32-bit block  1 32-bit
*/
std::vector<uint8> ChaCha20Block(std::vector<uint32> key, std::vector<uint32> nonce, uint32 blockCount)
{
    std::vector<uint32> state =
    {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        key[0], key[1], key[2], key[3],
        key[4], key[5], key[6], key[7],
        blockCount, nonce[0], nonce[1], nonce[2]
    };
    std::vector<uint32> init_state = state;

    for (int i = 1; i <= 10; i++)
    {
        QuarterRoundState(state, 0, 4, 8, 12);
        QuarterRoundState(state, 1, 5, 9, 13);
        QuarterRoundState(state, 2, 6, 10, 14);
        QuarterRoundState(state, 3, 7, 11, 15);

        QuarterRoundState(state, 0, 5, 10, 15);
        QuarterRoundState(state, 1, 6, 11, 12);
        QuarterRoundState(state, 2, 7, 8, 13);
        QuarterRoundState(state, 3, 4, 9, 14);
    }

    for (int i = 0; i < state.size(); i++)
    {
        state[i] = state[i] + init_state[i];
    }
    std::vector<uint8> serial_state = serialize(state);
    return serial_state;
}

// 2.4.  The ChaCha20 Encryption Algorithm
std::vector<uint8> ChaCha20Encrypt(std::vector<uint32> key, uint32 counter, std::vector<uint32> nonce, std::vector<uint8> plaintext)
{
    // pad key
    if (key.size() < 8)
        for (int i = key.size() - 1; i < 8; i++)
            key.push_back(0);

    if (key.size() > 8)
        for (int i = 8; i < key.size(); i++)
            key[i % 8] = key[i % 8] ^ key[i];

    std::vector<uint8> encrypted_message = {};
    for (int j = 0; j < (plaintext.size() / 64); j++)
    {
        std::vector<uint8> key_stream = ChaCha20Block(key, nonce, counter + j);
        std::vector<uint8> block = {};
        for (int x = j * 64; x <= (j * 64) + 63; x++)
            block.push_back(plaintext[x]);
        for (int y = 0; y < block.size(); y++)
            encrypted_message.push_back(block[y] ^ key_stream[y]);
    }
    if ((plaintext.size() % 64) != 0)
    {
        int j = plaintext.size() / 64;
        std::vector<uint8> key_stream = ChaCha20Block(key, nonce, counter + j);
        std::vector<uint8> block = {};
        for (int x = j * 64; x < plaintext.size(); x++)
            block.push_back(plaintext[x]);
        for (int y = 0; y < block.size(); y++)
            encrypted_message.push_back(block[y] ^ key_stream[y]);
    }
    return encrypted_message;
}

std::vector<uint8> ChaCha20Decrypt(std::vector<uint32> key, uint32 counter, std::vector<uint32> nonce, std::vector<uint8> ciphertext)
{
    // pad key
    if (key.size() < 8)
        for (int i = key.size() - 1; i < 8; i++)
            key.push_back(0);

    if (key.size() > 8)
        for (int i = 8; i < key.size(); i++)
            key[i % 8] = key[i % 8] ^ key[i];

    std::vector<uint8> plaintext = {};
    for (int j = 0; j < (ciphertext.size() / 64); j++)
    {
        std::vector<uint8> key_stream = ChaCha20Block(key, nonce, counter + j);
        std::vector<uint8> block = {};
        for (int x = j * 64; x <= (j * 64) + 63; x++)
            block.push_back(ciphertext[x]);
        for (int y = 0; y < block.size(); y++)
            plaintext.push_back(block[y] ^ key_stream[y]);
    }
    if ((ciphertext.size() % 64) != 0)
    {
        int j = ciphertext.size() / 64;
        std::vector<uint8> key_stream = ChaCha20Block(key, nonce, counter + j);
        std::vector<uint8> block = {};
        for (int x = j * 64; x < ciphertext.size(); x++)
            block.push_back(ciphertext[x]);
        for (int y = 0; y < block.size(); y++)
            plaintext.push_back(block[y] ^ key_stream[y]);
    }
    return plaintext;
}
