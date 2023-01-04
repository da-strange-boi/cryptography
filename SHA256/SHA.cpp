#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <math.h>
#include <bitset>
#include <iomanip>
#include <iterator>

// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

// 4.2.2 SHA-224 and SHA-256 Constants
const int w = 32;

class word {
private:
    uint32_t x;
public:
    word(uint32_t number) {
        x = number;
    }

    // overload plus operator
    word operator+ (const word & first) const {
        return word((uint32_t)(((int)x + (int)first.x) % 4294967296));
    }

    // class acts like a uint32_t
    operator uint32_t () const {
        return x;
    }

    // 2.2.2 Symbols and Operations
    word ROTL(int n) {
        return (x << n) | (x >> w - n);
    }
    word ROTR(int n) {
        return (x >> n) | (x << w - n);
    }
    word SHR(int n) {
        return x >> n;
    }
};

typedef uint8_t byte;
typedef std::vector<word> block;

const std::vector<word> K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

// My Functions
std::string printHashResult(std::vector<std::vector<word>> H) {
    std::stringstream stream;
    int N = H[0].size() - 1;
    for (int i = 0; i < H.size(); i++) {
        stream << std::setfill('0') << std::setw(8) << std::hex << H[i][N];
    }
    return stream.str();
}

word binaryToDecimal(std::string binary) {
    unsigned int decimal = 0;
    unsigned int bits = 1;
    for (int i = 0; i < binary.size(); i++) {
        char currentNum = binary[binary.size() - i - 1];
        if (currentNum == '1') {
            decimal += bits;
        }
        bits *= 2;
    }
    return (word)decimal;
}

// 4.1.2 SHA-224 and SHA-256 Functions
word Ch(word x, word y, word z) {
    return (x & y) ^ (~x & z);
}

word Maj(word x, word y, word z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

word sigma0(word x) {
    return x.ROTR(2) ^ x.ROTR(13) ^ x.ROTR(22);
}

word sigma1(word x) {
    return x.ROTR(6) ^ x.ROTR(11) ^ x.ROTR(25);
}

word lSigma0(word x) {
    return x.ROTR(7) ^ x.ROTR(18) ^ x.SHR(3);
}

word lSigma1(word x) {
    return x.ROTR(17) ^ x.ROTR(19) ^ x.SHR(10);
}

std::string SHA256(std::string message, bool binaryMode = false) {
    // 2,305,843,009,213,694,000 Bytes
    // 18,446,744,073,709,552,000 Bits
    if ((!binaryMode && message.size() * 8 >= pow(2, 64)) || (binaryMode && message.size() >= pow(2, 64))) {
        std::cout << "Message too large - input must be less than 2^64 bits" << std::endl;
        return "";
    }

    // 5.1.1  Padding the message
    std::string M;
    if (binaryMode) {
        for (char c : message) {
            M += c;
        }
    } else {
        for (char c : message) {
            M += std::bitset<8>(c).to_string();
        }
    }
    M += "1";

    // FIX FOR:
    // if message doesn't fill the size of a block, it squeezes in the length, regardless if it will fit inside the block
    if (((((message.size() * 8) / 512) + 1) * 512) - (message.size() * 8) < 65) {
        int paddingSizeForOrigBlock = (((message.size() * 8) / 512) + 1) * 512 - M.size();
        for (int i = 0; i < paddingSizeForOrigBlock; i++) {
            M += "0";
        }
        for (int i = 0; i < 448; i++) {
            M += "0";
        }
    } else {
        int paddingSize = ((((message.size() * 8) / 512) + 1) * 512) - (message.size() * 8) - 65;
        for (int i = 0; i < paddingSize; i++) {
            M += "0";
        }
    }

    M += std::bitset<64>(message.size() * 8).to_string();

    // 5.2.1 Parsing the Message
    // blocks [ block [ words ] ]
    std::vector<block> blocks;
    int index = 0;
    for (int bloc = 0; bloc < M.size() / 512; bloc++) { // number of blocks
        block tempBlock;
        for (int words = 0; words < 16; words++) { // gets each block
            std::string tempWord;
            for (int bit = 0; bit < w; bit++) { // gets each word
                tempWord += M[index];
                index++;
            }
            tempBlock.push_back(binaryToDecimal(tempWord));
        }
        blocks.push_back(tempBlock);
    }

    // 5.3.3 Setting Initial Hash Value
    // H[i][j]
    std::vector<std::vector<word>> H = {
        {0x6a09e667},
        {0xbb67ae85},
        {0x3c6ef372},
        {0xa54ff53a},
        {0x510e527f},
        {0x9b05688c},
        {0x1f83d9ab},
        {0x5be0cd19}
    };

    // 6.2.2 SHA-256 Hash Computation
    for (int i = 1; i-1 < blocks.size(); i++) {
        // Prepare the message schedule
        block W;
        for (word wd : blocks[i-1]) {
            W.push_back(wd);
        }
        for (int t = 16; t < 64; t++) {
            word TW = lSigma1(W[t-2]) + W[t-7] + lSigma0(W[t-15]) + W[t-16];
            W.push_back(TW);
        }

        // Initialize the eight working variables
        word a = H[0][i-1];
        word b = H[1][i-1];
        word c = H[2][i-1];
        word d = H[3][i-1];
        word e = H[4][i-1];
        word f = H[5][i-1];
        word g = H[6][i-1];
        word h = H[7][i-1];

        for (int t = 0; t < 64; t++) {
            word T1 = h + sigma1(e) + Ch(e,f,g) + K[t] + W[t];
            word T2 = sigma0(a) + Maj(a,b,c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // Compute the ith intermediate hash value Hi
        H[0].push_back(a + H[0][i-1]);
        H[1].push_back(b + H[1][i-1]);
        H[2].push_back(c + H[2][i-1]);
        H[3].push_back(d + H[3][i-1]);
        H[4].push_back(e + H[4][i-1]);
        H[5].push_back(f + H[5][i-1]);
        H[6].push_back(g + H[6][i-1]);
        H[7].push_back(h + H[7][i-1]);
    }

    return printHashResult(H);
}

// -------------------------------------------------------------------------------
int main(int argc, char *argv[]) {
    std::cout << SHA256("text to be hashed") << std::endl;
    return 0;
}
