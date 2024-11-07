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
- https://iacr.org/workshops/ches/ches2002/presentations/Bertoni.pdf (for fast AES)
*/

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include "AES128.h"
#include "AES_Serial.h"

void print_byte_hex(uchar text[], uint len)
{
    for (int i = 0; i < len; i++)
    {
        std::cout << std::hex << (int)text[i] << " ";
    }
    std::cout << std::endl;
}

void print_word_hex(uint32 text[], uint len)
{
    for (int i = 0; i < len; i++)
    {
        std::cout << std::hex << ((text[i] >> 24) & 0xff) << " " << ((text[i] >> 16) & 0xff) << " " << ((text[i] >> 8) & 0xff) << " " << (text[i] & 0xff) << " ";
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
#pragma region AES128_serial

/*
ECB block cipher mode (cipher is applied directly and indepentently to each block)
*/
void AES128_Serial::encrypt(uchar input[], uchar output[], int len)
{
    if (len % BLOCK_STATES != 0)
    {
        std::cerr << "[Error] Input size must be multiple of " << BLOCK_STATES << " bytes" << std::endl;
        exit(1);
    }
    for (int i = 0; i < len; i += BLOCK_STATES)
    {
        encrypt_block(input + i, output + i);
    }
}

void AES128_Serial::decrypt(uchar input[], uchar output[], int len)
{
    if (len % BLOCK_STATES != 0)
    {
        std::cerr << "[Error] Input size must be multiple of " << BLOCK_STATES << " bytes" << std::endl;
        exit(1);
    }
    for (int i = 0; i < len; i += BLOCK_STATES)
    {
        decrypt_block(input + i, output + i);
    }
}

#pragma endregion

/*
4 steps involved in standard AES encryption:
addRoundKey, substituteBytes, permutation, multiplication
*/
#pragma region AES128_serial_standard

AES128_Serial_Std::AES128_Serial_Std(std::string key)
{
    if (key.size() != BLOCK_STATES)
    {
        std::cerr << "[Error] Key size must be BLOCK_STATES bytes" << std::endl;
        exit(1);
    }
    memcpy(this->key, key.c_str(), BLOCK_STATES); // get cipher key
    key_expansion();
}

/*
Expand the original key to ROUND_SIZE + 1 keys
*/
void AES128_Serial_Std::key_expansion()
{
    uint32 w[4];
    uint32 w_new[4];
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
            key[i * BLOCK_STATES + j * 4] = (w[j] >> 24) & 0xff;
            key[i * BLOCK_STATES + j * 4 + 1] = (w[j] >> 16) & 0xff;
            key[i * BLOCK_STATES + j * 4 + 2] = (w[j] >> 8) & 0xff;
            key[i * BLOCK_STATES + j * 4 + 3] = w[j] & 0xff;
        }
    }

#ifdef debug
    std::cout << "Key: " << std::endl;
    for (int i = 0; i <= ROUND_SIZE; i++)
    {
        for (int j = 0; j < BLOCK_STATES; j++)
        {
            std::cout << std::hex << (int)key[i * BLOCK_STATES + j] << " ";
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;
#endif
}

#pragma region encryption

void AES128_Serial_Std::encrypt_block(uchar input[BLOCK_STATES], uchar output[BLOCK_STATES])
{
#ifdef debug
    std::cout << "----Encryption----" << std::endl;
#endif
    uchar state[BLOCK_STATES];
    memcpy(state, input, BLOCK_STATES);

    // round 0
#ifdef debug
    std::cout << "Round 0" << std::endl;
#endif
    aes_4_addRoundKey(state, 0);
    // round 1 to 9
    for (int i = 1; i < ROUND_SIZE; i++)
    {
#ifdef debug
        std::cout << std::endl
                  << "Round " << i << std::endl;
#endif
        aes_1_substituteBytes(state);
        aes_2_permutation(state);
        aes_3_multiplication(state);
        aes_4_addRoundKey(state, i);
    }
    // round 10: substituteBytes, shiftRows, addRoundKey (no mixColumns)
#ifdef debug
    std::cout << std::endl
              << "Round " << ROUND_SIZE << std::endl;
#endif
    aes_1_substituteBytes(state);
    aes_2_permutation(state);
    aes_4_addRoundKey(state, ROUND_SIZE);

    memcpy(output, state, BLOCK_STATES);
}

void AES128_Serial_Std::aes_1_substituteBytes(uchar state[BLOCK_STATES]) // (字节代换)
{
    for (int i = 0; i < BLOCK_STATES; i++)
    {
        state[i] = sbox[state[i]];
    }
#ifdef debug
    std::cout << "[substituteBytes]: ";
    print_byte_hex(state, BLOCK_STATES);
#endif
}

void AES128_Serial_Std::aes_2_permutation(uchar state[BLOCK_STATES]) // shift row (行移位)
{
    uchar state_t[BLOCK_STATES];
    memcpy(state_t, state, BLOCK_STATES);
    for (int i = 0; i < 4; i++) // each column
    {
        for (int j = 0; j < 4; j++) // each row
        {
            state[i * 4 + j] = state_t[((i + j) % 4) * 4 + j];
        }
    }
#ifdef debug
    std::cout << "[permutation]: ";
    print_byte_hex(state, BLOCK_STATES);
#endif
}

void AES128_Serial_Std::aes_3_multiplication(uchar state[BLOCK_STATES]) // mix columns (列混合)
{
    uchar state_t[BLOCK_STATES];
    memcpy(state_t, state, BLOCK_STATES);
    // state = M * Transpose(state_t);
    for (int i = 0; i < 4; i++) // each column
    {
        for (int j = 0; j < 4; j++) // each row
        {
            // state[i * 4 + j] =  row j of M * column i of state_t
            state[i * 4 + j] = gfmul(M[j * 4], state_t[i * 4]) ^ gfmul(M[j * 4 + 1], state_t[i * 4 + 1]) ^ gfmul(M[j * 4 + 2], state_t[i * 4 + 2]) ^ gfmul(M[j * 4 + 3], state_t[i * 4 + 3]);
        }
    }
#ifdef debug
    std::cout << "[multiplication]: ";
    print_byte_hex(state, BLOCK_STATES);
#endif
}

void AES128_Serial_Std::aes_4_addRoundKey(uchar state[BLOCK_STATES], uint round) // (轮密钥加)
{
    for (int i = 0; i < BLOCK_STATES; i++)
    {
        state[i] ^= key[round * BLOCK_STATES + i];
    }
#ifdef debug
    std::cout << "[addRoundKey]: ";
    print_byte_hex(state, BLOCK_STATES);
#endif
}

#pragma endregion encryption

#pragma region decryption

void AES128_Serial_Std::decrypt_block(uchar input[BLOCK_STATES], uchar output[BLOCK_STATES])
{
#ifdef debug
    std::cout << "----Decryption----" << std::endl;
#endif
    uchar state[BLOCK_STATES];
    memcpy(state, input, BLOCK_STATES);

    // round ROUND_SIZE
#ifdef debug
    std::cout << "Round " << ROUND_SIZE << std::endl;
#endif
    aes_4_addRoundKey(state, ROUND_SIZE);
    // round ROUND_SIZE-1 to 1
    for (int i = ROUND_SIZE - 1; i > 0; i--)
    {
#ifdef debug
        std::cout << std::endl
                  << "Round " << i << std::endl;
#endif
        aes_inv_2_permutation(state);
        aes_inv_1_substituteBytes(state);
        aes_4_addRoundKey(state, i);
        aes_inv_3_multiplication(state);
    }
    // Round 0
#ifdef debug
    std::cout << "Round 0" << std::endl;
#endif
    aes_inv_1_substituteBytes(state);
    aes_inv_2_permutation(state);
    aes_4_addRoundKey(state, 0);

    memcpy(output, state, BLOCK_STATES);
}

void AES128_Serial_Std::aes_inv_1_substituteBytes(uchar state[BLOCK_STATES])
{
    for (int i = 0; i < BLOCK_STATES; i++)
    {
        state[i] = inv_sbox[state[i]];
    }
#ifdef debug
    std::cout << "[inv_substituteBytes]: ";
    print_byte_hex(state, BLOCK_STATES);
#endif
}

void AES128_Serial_Std::aes_inv_2_permutation(uchar state[BLOCK_STATES])
{
    uchar state_t[BLOCK_STATES];
    memcpy(state_t, state, BLOCK_STATES);
    for (int i = 0; i < 4; i++) // each row
    {
        for (int j = 0; j < 4; j++) // each column
        {
            state[i * 4 + j] = state_t[((i - j + 4) % 4) * 4 + j];
        }
    }
#ifdef debug
    std::cout << "[inv_permutation]: ";
    print_byte_hex(state, BLOCK_STATES);
#endif
}

void AES128_Serial_Std::aes_inv_3_multiplication(uchar state[BLOCK_STATES])
{
    uchar state_t[BLOCK_STATES];
    memcpy(state_t, state, BLOCK_STATES);
    // state = M * Transpose(state_t);
    for (int i = 0; i < 4; i++) // each row
    {
        for (int j = 0; j < 4; j++) // each column
        {
            // state[i * 4 + j] = row i of state_t * row j of inv_M
            state[i * 4 + j] = gfmul(inv_M[j * 4], state_t[i * 4]) ^ gfmul(inv_M[j * 4 + 1], state_t[i * 4 + 1]) ^ gfmul(inv_M[j * 4 + 2], state_t[i * 4 + 2]) ^ gfmul(inv_M[j * 4 + 3], state_t[i * 4 + 3]);
        }
    }
#ifdef debug

    std::cout << "[inv_multiplication]: ";
    print_byte_hex(state, BLOCK_STATES);
#endif
}

#pragma endregion decryption

#pragma endregion AES128_serial_standard

/*
Fast AES128 use 4 T-tables.
*/
#pragma region AES128_serial_fast

AES128_Serial_Fast::AES128_Serial_Fast(std::string key)
{
    if (key.size() != BLOCK_STATES)
    {
        std::cerr << "[Error] Key size must be BLOCK_STATES bytes" << std::endl;
        exit(1);
    }
    this->key[0] = (uchar)key[0] << 24 | (uchar)key[1] << 16 | (uchar)key[2] << 8 | (uchar)key[3];
    this->key[1] = (uchar)key[4] << 24 | (uchar)key[5] << 16 | (uchar)key[6] << 8 | (uchar)key[7];
    this->key[2] = (uchar)key[8] << 24 | (uchar)key[9] << 16 | (uchar)key[10] << 8 | (uchar)key[11];
    this->key[3] = (uchar)key[12] << 24 | (uchar)key[13] << 16 | (uchar)key[14] << 8 | (uchar)key[15];
    key_expansion();
}

/*
Besides round keys for encryption, also need a set of keys for decryption.
*/
void AES128_Serial_Fast::key_expansion()
{
    uint32 w[4];
    uint32 w_new[4];
    w[0] = key[0];
    w[1] = key[1];
    w[2] = key[2];
    w[3] = key[3];
    for (int i = 1; i <= ROUND_SIZE; ++i) // each round
    {
        w_new[0] = w[0] ^ (sbox[(w[3] >> 24) & 0xff]) ^ (sbox[(w[3] >> 16) & 0xff] << 24) ^ (sbox[(w[3] >> 8) & 0xff] << 16) ^ (sbox[w[3] & 0xff] << 8) ^ (rcon[i - 1] << 24);
        w_new[1] = w[1] ^ w_new[0];
        w_new[2] = w[2] ^ w_new[1];
        w_new[3] = w[3] ^ w_new[2];
        for (int j = 0; j < 4; ++j) // each word
        {
            w[j] = w_new[j];
            key[i * 4 + j] = w_new[j];
        }
    }

    // key_dec = key for round 0 and ROUND_SIZE
    key_dec[0] = key[0];
    key_dec[1] = key[1];
    key_dec[2] = key[2];
    key_dec[3] = key[3];
    key_dec[ROUND_SIZE * 4] = key[ROUND_SIZE * 4];
    key_dec[ROUND_SIZE * 4 + 1] = key[ROUND_SIZE * 4 + 1];
    key_dec[ROUND_SIZE * 4 + 2] = key[ROUND_SIZE * 4 + 2];
    key_dec[ROUND_SIZE * 4 + 3] = key[ROUND_SIZE * 4 + 3];
    // key_dec = inv_multiplication(key) for round 1 to ROUND_SIZE-1
    uchar states[16];
    for (int i = 1; i <= ROUND_SIZE - 1; ++i)
    {
        // load key to states
        for (int j = 0; j < 4; ++j)
        {
            states[j * 4] = (key[i * 4 + j] >> 24) & 0xff;
            states[j * 4 + 1] = (key[i * 4 + j] >> 16) & 0xff;
            states[j * 4 + 2] = (key[i * 4 + j] >> 8) & 0xff;
            states[j * 4 + 3] = key[i * 4 + j] & 0xff;
        }
        inv_multiplication(states);
        // load states to key
        for (int j = 0; j < 4; ++j)
        {
            key_dec[i * 4 + j] = (states[j * 4] << 24) | (states[j * 4 + 1] << 16) | (states[j * 4 + 2] << 8) | states[j * 4 + 3];
        }
    }

#ifdef debug
    // print key
    std::cout << "Key:" << std::endl;
    for (int i = 0; i < 11; ++i)
    {
        print_word_hex(key + i * 4, 4);
    }
    std::cout << "Key_dec:" << std::endl;
    for (int i = 0; i < 11; ++i)
    {
        print_word_hex(key_dec + i * 4, 4);
    }
#endif
}

void AES128_Serial_Fast::encrypt_block(uchar input[BLOCK_STATES], uchar output[BLOCK_STATES])
{
#ifdef debug
    std::cout << "----Encryption----" << std::endl;
#endif

    uint32 w[BLOCK_WORDS];
    uint32 w_new[BLOCK_WORDS];

    // get words from input
    w[0] = (input[0] << 24) | (input[1] << 16) | (input[2] << 8) | input[3];
    w[1] = (input[4] << 24) | (input[5] << 16) | (input[6] << 8) | input[7];
    w[2] = (input[8] << 24) | (input[9] << 16) | (input[10] << 8) | input[11];
    w[3] = (input[12] << 24) | (input[13] << 16) | (input[14] << 8) | input[15];

    // round 0
    w[0] ^= key[0];
    w[1] ^= key[1];
    w[2] ^= key[2];
    w[3] ^= key[3];
#ifdef debug
    std::cout << "Round 0" << ": ";
    print_word_hex(w, BLOCK_WORDS);
#endif
    // round 1 to ROUND_SIZE-1
    for (int r = 1; r < ROUND_SIZE; r++)
    {
        w_new[0] = T0[(w[0] >> 24) & 0xff] ^ T1[(w[1] >> 16) & 0xff] ^ T2[(w[2] >> 8) & 0xff] ^ T3[w[3] & 0xff] ^ key[r * 4];
        w_new[1] = T0[(w[1] >> 24) & 0xff] ^ T1[(w[2] >> 16) & 0xff] ^ T2[(w[3] >> 8) & 0xff] ^ T3[w[0] & 0xff] ^ key[r * 4 + 1];
        w_new[2] = T0[(w[2] >> 24) & 0xff] ^ T1[(w[3] >> 16) & 0xff] ^ T2[(w[0] >> 8) & 0xff] ^ T3[w[1] & 0xff] ^ key[r * 4 + 2];
        w_new[3] = T0[(w[3] >> 24) & 0xff] ^ T1[(w[0] >> 16) & 0xff] ^ T2[(w[1] >> 8) & 0xff] ^ T3[w[2] & 0xff] ^ key[r * 4 + 3];
        memcpy(w, w_new, BLOCK_STATES);
#ifdef debug
        std::cout << "Round " << r << ": ";
        print_word_hex(w, BLOCK_WORDS);
#endif
    }
    // round ROUND_SIZE: substituteBytes, shiftRows, addRoundKey (no mixColumns)
    w_new[0] = (sbox[(w[0] >> 24) & 0xff] << 24) ^ (sbox[(w[1] >> 16) & 0xff] << 16) ^ (sbox[(w[2] >> 8) & 0xff] << 8) ^ sbox[w[3] & 0xff] ^ key[ROUND_SIZE * 4];
    w_new[1] = (sbox[(w[1] >> 24) & 0xff] << 24) ^ (sbox[(w[2] >> 16) & 0xff] << 16) ^ (sbox[(w[3] >> 8) & 0xff] << 8) ^ sbox[w[0] & 0xff] ^ key[ROUND_SIZE * 4 + 1];
    w_new[2] = (sbox[(w[2] >> 24) & 0xff] << 24) ^ (sbox[(w[3] >> 16) & 0xff] << 16) ^ (sbox[(w[0] >> 8) & 0xff] << 8) ^ sbox[w[1] & 0xff] ^ key[ROUND_SIZE * 4 + 2];
    w_new[3] = (sbox[(w[3] >> 24) & 0xff] << 24) ^ (sbox[(w[0] >> 16) & 0xff] << 16) ^ (sbox[(w[1] >> 8) & 0xff] << 8) ^ sbox[w[2] & 0xff] ^ key[ROUND_SIZE * 4 + 3];
#ifdef debug
    std::cout << "Round " << ROUND_SIZE << ": ";
    print_word_hex(w_new, BLOCK_WORDS);
#endif

    // get output
    for (int i = 0; i < BLOCK_WORDS; ++i)
    {
        output[i * 4] = (w_new[i] >> 24) & 0xff;
        output[i * 4 + 1] = (w_new[i] >> 16) & 0xff;
        output[i * 4 + 2] = (w_new[i] >> 8) & 0xff;
        output[i * 4 + 3] = w_new[i] & 0xff;
    }
}

void AES128_Serial_Fast::inv_multiplication(uchar state[BLOCK_STATES])
{
    uchar state_t[BLOCK_STATES];
    memcpy(state_t, state, BLOCK_STATES);
    // state = M * Transpose(state_t);
    for (int i = 0; i < 4; i++) // each row
    {
        for (int j = 0; j < 4; j++) // each column
        {
            // state[i * 4 + j] = row i of state_t * row j of inv_M
            state[i * 4 + j] = gfmul(inv_M[j * 4], state_t[i * 4]) ^ gfmul(inv_M[j * 4 + 1], state_t[i * 4 + 1]) ^ gfmul(inv_M[j * 4 + 2], state_t[i * 4 + 2]) ^ gfmul(inv_M[j * 4 + 3], state_t[i * 4 + 3]);
        }
    }
}

void AES128_Serial_Fast::decrypt_block(uchar input[BLOCK_STATES], uchar output[BLOCK_STATES])
{
#ifdef debug
    std::cout << "----Decryption----" << std::endl;
#endif

    uint32 w[BLOCK_WORDS];
    uint32 w_new[BLOCK_WORDS];

    // get words from input
    w[0] = (input[0] << 24) | (input[1] << 16) | (input[2] << 8) | input[3];
    w[1] = (input[4] << 24) | (input[5] << 16) | (input[6] << 8) | input[7];
    w[2] = (input[8] << 24) | (input[9] << 16) | (input[10] << 8) | input[11];
    w[3] = (input[12] << 24) | (input[13] << 16) | (input[14] << 8) | input[15];

    // round ROUND_SIZE
    w[0] ^= key_dec[ROUND_SIZE * 4];
    w[1] ^= key_dec[ROUND_SIZE * 4 + 1];
    w[2] ^= key_dec[ROUND_SIZE * 4 + 2];
    w[3] ^= key_dec[ROUND_SIZE * 4 + 3];
#ifdef debug
    std::cout << "Round " << ROUND_SIZE << ": ";
    print_word_hex(w, BLOCK_WORDS);
#endif
    // round ROUND_SIZE-1 to 1
    for (int i = ROUND_SIZE - 1; i > 0; i--)
    {
        w_new[0] = inv_T0[(w[0] >> 24) & 0xff] ^ inv_T1[(w[3] >> 16) & 0xff] ^ inv_T2[(w[2] >> 8) & 0xff] ^ inv_T3[w[1] & 0xff] ^ key_dec[i * 4];
        w_new[1] = inv_T0[(w[1] >> 24) & 0xff] ^ inv_T1[(w[0] >> 16) & 0xff] ^ inv_T2[(w[3] >> 8) & 0xff] ^ inv_T3[w[2] & 0xff] ^ key_dec[i * 4 + 1];
        w_new[2] = inv_T0[(w[2] >> 24) & 0xff] ^ inv_T1[(w[1] >> 16) & 0xff] ^ inv_T2[(w[0] >> 8) & 0xff] ^ inv_T3[w[3] & 0xff] ^ key_dec[i * 4 + 2];
        w_new[3] = inv_T0[(w[3] >> 24) & 0xff] ^ inv_T1[(w[2] >> 16) & 0xff] ^ inv_T2[(w[1] >> 8) & 0xff] ^ inv_T3[w[0] & 0xff] ^ key_dec[i * 4 + 3];
        memcpy(w, w_new, BLOCK_STATES);
#ifdef debug
        std::cout << "Round " << i << ": ";
        print_word_hex(w, BLOCK_WORDS);
#endif
    }

    // round 0: substituteBytes, shiftRows, addRoundKey
    w_new[0] = (inv_sbox[(w[0] >> 24) & 0xff] << 24) ^ (inv_sbox[(w[3] >> 16) & 0xff] << 16) ^ (inv_sbox[(w[2] >> 8) & 0xff] << 8) ^ inv_sbox[w[1] & 0xff] ^ key_dec[0];
    w_new[1] = (inv_sbox[(w[1] >> 24) & 0xff] << 24) ^ (inv_sbox[(w[0] >> 16) & 0xff] << 16) ^ (inv_sbox[(w[3] >> 8) & 0xff] << 8) ^ inv_sbox[w[2] & 0xff] ^ key_dec[1];
    w_new[2] = (inv_sbox[(w[2] >> 24) & 0xff] << 24) ^ (inv_sbox[(w[1] >> 16) & 0xff] << 16) ^ (inv_sbox[(w[0] >> 8) & 0xff] << 8) ^ inv_sbox[w[3] & 0xff] ^ key_dec[2];
    w_new[3] = (inv_sbox[(w[3] >> 24) & 0xff] << 24) ^ (inv_sbox[(w[2] >> 16) & 0xff] << 16) ^ (inv_sbox[(w[1] >> 8) & 0xff] << 8) ^ inv_sbox[w[0] & 0xff] ^ key_dec[3];
#ifdef debug
    std::cout << "Round 0: ";
    print_word_hex(w_new, BLOCK_WORDS);
#endif

    // get output
    for (int i = 0; i < BLOCK_WORDS; ++i)
    {
        output[i * 4] = (w_new[i] >> 24) & 0xff;
        output[i * 4 + 1] = (w_new[i] >> 16) & 0xff;
        output[i * 4 + 2] = (w_new[i] >> 8) & 0xff;
        output[i * 4 + 3] = w_new[i] & 0xff;
    }
}

#pragma endregion AES128_serial_fast