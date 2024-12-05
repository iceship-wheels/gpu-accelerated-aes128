#include "AES_Parallel.h"
/*
Author: Qiuhong Chen
Date Created: 2024/11/4
*/

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include "AES128.h"
#include "AES_Parallel.h"

/*
Round keys are precomputed by the host.
*/
void AES128_Parallel::key_expansion()
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
}

void AES128_Parallel::inv_multiplication(uchar state[BLOCK_STATES])
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

AES128_Parallel::AES128_Parallel(std::string key)
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