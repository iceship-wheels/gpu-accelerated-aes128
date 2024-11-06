/*
Author: Qiuhong Chen
Date Created: 2024/11/4

Description:
- Standard AES128 + fast AES128 (T-table)
- 10 rounds, serial

Reference:
- https://ieeexplore.ieee.org/document/8252225
- https://arxiv.org/abs/1902.05234
- https://legacy.cryptool.org/en/cto/aes-step-by-step (for standard AES)
*/

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include "AES128.h"

#define ROUND_SIZE 10 // 10 rounds of encryption
#define BLOCK_SIZE 16 // 16 bytes for AES128

void print_text_hex(uchar text[], uint len)
{
    for (int i = 0; i < len; i++)
    {
        std::cout << std::hex << (int)text[i] << " ";
    }
    std::cout << std::endl;
}

/*
Key & block are both 16 bytes
Assume column-major stored
[0 4 8 12]
[1 5 9 13]
[2 6 10 14]
[3 7 11 15]
*/
class AES128_serial
{
protected:
    uchar key[BLOCK_SIZE * (ROUND_SIZE + 1)];
    const uchar rcon[ROUND_SIZE] = {
        0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1b, 0x36};

    void key_expansion()
    {
        uint32_t w[4];
        uint32_t w_new[4];
        // w[0]= K0K1K2K3, w[1]= K4K5K6K7, w[2]= K8K9K10K11, w[3]= K12K13K14K15
        for (int i = 0; i < 4; ++i)
        {
            w[i] = (key[i * 4] << 24) | (key[i * 4 + 1] << 16) | (key[i * 4 + 2] << 8) | key[i * 4 + 3];
        }
        for (int i = 1; i <= ROUND_SIZE; ++i) // each round
        {
            w_new[0] = w[0] ^ (sbox[(w[3] >> 24) & 0xff]) ^ (sbox[(w[3] >> 16) & 0xff] << 24) ^ (sbox[(w[3] >> 8) & 0xff] << 16) ^ (sbox[w[3] & 0xff] << 8) ^ (rcon[i - 1] << 24);
            w_new[1] = w[1] ^ w_new[0];
            w_new[2] = w[2] ^ w_new[1];
            w_new[3] = w[3] ^ w_new[2];
            for (int j = 0; j < 4; ++j) // each word
            {
                w[j] = w_new[j];
                key[i * BLOCK_SIZE + j * 4] = (w[j] >> 24) & 0xff;
                key[i * BLOCK_SIZE + j * 4 + 1] = (w[j] >> 16) & 0xff;
                key[i * BLOCK_SIZE + j * 4 + 2] = (w[j] >> 8) & 0xff;
                key[i * BLOCK_SIZE + j * 4 + 3] = w[j] & 0xff;
            }
        }
    }

public:
    virtual void encrypt(uchar input[], uchar output[], int len) = 0;
    virtual void decrypt(uchar input[], uchar output[], int len) = 0;
};

/*
4 steps:
addRoundKey, substituteBytes, permutation, multiplication
*/
class AES128_serial_standard : public AES128_serial
{
protected:
    // for mix_columns
    const uchar M[BLOCK_SIZE] = {
        0x02, 0x03, 0x01, 0x01,
        0x01, 0x02, 0x03, 0x01,
        0x01, 0x01, 0x02, 0x03,
        0x03, 0x01, 0x01, 0x02};
    const uchar inv_M[BLOCK_SIZE] = {
        0x0e, 0x0b, 0x0d, 0x09,
        0x09, 0x0e, 0x0b, 0x0d,
        0x0d, 0x09, 0x0e, 0x0b,
        0x0b, 0x0d, 0x09, 0x0e};

    /*
    ========================encryption========================
    */

    void encrypt_block(uchar input[BLOCK_SIZE], uchar output[BLOCK_SIZE])
    {
        uchar state[BLOCK_SIZE];
        memcpy(state, input, BLOCK_SIZE);

        aes_4_addRoundKey(state, 0);
        // for ROUND_SIZE - 1 rounds
        for (int i = 1; i < ROUND_SIZE; i++)
        {
#ifdef debug_enc
            std::cout << std::endl
                      << "Round " << i << std::endl;
#endif
            aes_1_substituteBytes(state);
            aes_2_permutation(state);
            aes_3_multiplication(state);
            aes_4_addRoundKey(state, i);
        }
        // for the last round
        aes_1_substituteBytes(state);
        aes_2_permutation(state);
        aes_4_addRoundKey(state, ROUND_SIZE);

        memcpy(output, state, BLOCK_SIZE);
    }

    void aes_1_substituteBytes(uchar state[BLOCK_SIZE]) // (字节代换)
    {
        for (int i = 0; i < BLOCK_SIZE; i++)
        {
            state[i] = sbox[state[i]];
        }
#ifdef debug_enc
        std::cout << "[substituteBytes]: ";
        print_text_hex(state, BLOCK_SIZE);
#endif
    }

    void aes_2_permutation(uchar state[BLOCK_SIZE]) // shift row (行移位)
    {
        uchar state_t[BLOCK_SIZE];
        memcpy(state_t, state, BLOCK_SIZE);
        for (int i = 0; i < 4; i++) // each column
        {
            for (int j = 0; j < 4; j++) // each row
            {
                state[i * 4 + j] = state_t[((i + j) % 4) * 4 + j];
            }
        }
#ifdef debug_enc
        std::cout << "[permutation]: ";
        print_text_hex(state, BLOCK_SIZE);
#endif
    }

    void aes_3_multiplication(uchar state[BLOCK_SIZE]) // mix columns (列混合)
    {
        uchar state_t[BLOCK_SIZE];
        memcpy(state_t, state, BLOCK_SIZE);
        // state = M * Transpose(state_t);
        for (int i = 0; i < 4; i++) // each column
        {
            for (int j = 0; j < 4; j++) // each row
            {
                // state[i * 4 + j] =  row j of M * column i of state_t
                state[i * 4 + j] = gfmul(M[j * 4], state_t[i * 4]) ^ gfmul(M[j * 4 + 1], state_t[i * 4 + 1]) ^ gfmul(M[j * 4 + 2], state_t[i * 4 + 2]) ^ gfmul(M[j * 4 + 3], state_t[i * 4 + 3]);
            }
        }
#ifdef debug_enc
        std::cout << "[multiplication]: ";
        print_text_hex(state, BLOCK_SIZE);
#endif
    }

    void aes_4_addRoundKey(uchar state[BLOCK_SIZE], uint round) // (轮密钥加)
    {
        for (int i = 0; i < BLOCK_SIZE; i++)
        {
            state[i] ^= key[round * BLOCK_SIZE + i];
        }
#ifdef debug_dec
        std::cout << "[addRoundKey]: ";
        print_text_hex(state, BLOCK_SIZE);
#endif
    }

    /*
    ========================decryption========================
    */

    void decrypt_block(uchar input[BLOCK_SIZE], uchar output[BLOCK_SIZE])
    {
        uchar state[BLOCK_SIZE];
        memcpy(state, input, BLOCK_SIZE);

        aes_4_addRoundKey(state, ROUND_SIZE);
        // for ROUND_SIZE - 1 rounds
        for (int i = ROUND_SIZE - 1; i > 0; i--)
        {
#ifdef debug_dec
            std::cout << std::endl
                      << "Round " << i << std::endl;
#endif
            aes_inv_2_permutation(state);
            aes_inv_1_substituteBytes(state);
            aes_4_addRoundKey(state, i);
            aes_inv_3_multiplication(state);
        }
        // for the last round
        aes_inv_1_substituteBytes(state);
        aes_inv_2_permutation(state);
        aes_4_addRoundKey(state, 0);

        memcpy(output, state, BLOCK_SIZE);
    }

    void aes_inv_1_substituteBytes(uchar state[BLOCK_SIZE])
    {
        for (int i = 0; i < BLOCK_SIZE; i++)
        {
            state[i] = sbox_inv[state[i]];
        }
#ifdef debug_dec
        std::cout << "[inv_substituteBytes]: ";
        print_text_hex(state, BLOCK_SIZE);
#endif
    }

    void aes_inv_2_permutation(uchar state[BLOCK_SIZE])
    {
        uchar state_t[BLOCK_SIZE];
        memcpy(state_t, state, BLOCK_SIZE);
        for (int i = 0; i < 4; i++) // each row
        {
            for (int j = 0; j < 4; j++) // each column
            {
                state[i * 4 + j] = state_t[((i - j + 4) % 4) * 4 + j];
            }
        }
#ifdef debug_dec
        std::cout << "[inv_permutation]: ";
        print_text_hex(state, BLOCK_SIZE);
#endif
    }

    void aes_inv_3_multiplication(uchar state[BLOCK_SIZE])
    {
        uchar state_t[BLOCK_SIZE];
        memcpy(state_t, state, BLOCK_SIZE);
        // state = M * Transpose(state_t);
        for (int i = 0; i < 4; i++) // each row
        {
            for (int j = 0; j < 4; j++) // each column
            {
                // state[i * 4 + j] = row i of state_t * row j of inv_M
                state[i * 4 + j] = gfmul(inv_M[j * 4], state_t[i * 4]) ^ gfmul(inv_M[j * 4 + 1], state_t[i * 4 + 1]) ^ gfmul(inv_M[j * 4 + 2], state_t[i * 4 + 2]) ^ gfmul(inv_M[j * 4 + 3], state_t[i * 4 + 3]);
            }
        }
#ifdef debug_dec

        std::cout << "[inv_multiplication]: ";
        print_text_hex(state, BLOCK_SIZE);
#endif
    }

public:
    AES128_serial_standard(std::string key)
    {
        if (key.size() != BLOCK_SIZE)
        {
            std::cerr << "[Error] Key size must be BLOCK_SIZE bytes" << std::endl;
            exit(1);
        }
        memcpy(this->key, key.c_str(), BLOCK_SIZE); // get cipher key
        key_expansion();
#ifdef debug_dec
        std::cout << "Cipher key: ";
        print_text_hex(this->key, BLOCK_SIZE);
#endif
    }

    virtual void encrypt(uchar input[], uchar output[], int len)
    {
        if (len % BLOCK_SIZE != 0)
        {
            std::cerr << "[Error] Input size must be multiple of " << BLOCK_SIZE << " bytes" << std::endl;
            exit(1);
        }
        for (int i = 0; i < len; i += BLOCK_SIZE)
        {
            encrypt_block(input + i, output + i);
        }
    }

    virtual void decrypt(uchar input[], uchar output[], int len)
    {
        if (len % BLOCK_SIZE != 0)
        {
            std::cerr << "[Error] Input size must be multiple of " << BLOCK_SIZE << " bytes" << std::endl;
            exit(1);
        }
        for (int i = 0; i < len; i += BLOCK_SIZE)
        {
            decrypt_block(input + i, output + i);
        }
    }
};

/*
4 T-tables
*/
class AES128_fast : public AES128_serial
{
};
