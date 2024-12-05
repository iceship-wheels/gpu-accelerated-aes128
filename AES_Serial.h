/*
Author: Qiuhong Chen
Date Created: 2024/11/4
*/

#ifndef __AES_SERIAL_H__
#define __AES_SERIAL_H__
#include "AES128.h"
#include <string>

// #define debug
#define ROUND_SIZE 10   // 10 rounds of encryption
#define BLOCK_STATES 16 // 16 bytes in a block
#define BLOCK_WORDS 4   // or 4 words in a block

class AES128_Serial
{
protected:
    const uchar M[BLOCK_STATES] = {
        0x02, 0x03, 0x01, 0x01,
        0x01, 0x02, 0x03, 0x01,
        0x01, 0x01, 0x02, 0x03,
        0x03, 0x01, 0x01, 0x02};
    const uchar inv_M[BLOCK_STATES] = {
        0x0e, 0x0b, 0x0d, 0x09,
        0x09, 0x0e, 0x0b, 0x0d,
        0x0d, 0x09, 0x0e, 0x0b,
        0x0b, 0x0d, 0x09, 0x0e};
    const uchar rcon[ROUND_SIZE] = {
        0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1b, 0x36};

    virtual void encrypt_block(uchar input[BLOCK_STATES], uchar output[BLOCK_STATES]) = 0;
    virtual void decrypt_block(uchar input[BLOCK_STATES], uchar output[BLOCK_STATES]) = 0;

public:
    void encrypt(uchar input[], uchar output[], int len);
    void decrypt(uchar input[], uchar output[], int len);
};

class AES128_Serial_Std : public AES128_Serial
{
protected:
    uchar key[BLOCK_STATES * (ROUND_SIZE + 1)];

    void key_expansion();

    /*
    ========================encryption========================
    */
    virtual void encrypt_block(uchar input[BLOCK_STATES], uchar output[BLOCK_STATES]);
    void aes_1_substituteBytes(uchar state[BLOCK_STATES]);
    void aes_2_permutation(uchar state[BLOCK_STATES]);
    void aes_3_multiplication(uchar state[BLOCK_STATES]);
    void aes_4_addRoundKey(uchar state[BLOCK_STATES], uint round);

    /*
    ========================decryption========================
    */
    virtual void decrypt_block(uchar input[BLOCK_STATES], uchar output[BLOCK_STATES]);
    void aes_inv_1_substituteBytes(uchar state[BLOCK_STATES]);
    void aes_inv_2_permutation(uchar state[BLOCK_STATES]);
    void aes_inv_3_multiplication(uchar state[BLOCK_STATES]);

public:
    AES128_Serial_Std(std::string key);
};

class AES128_Serial_Fast : public AES128_Serial
{
protected:
    uint32 key[BLOCK_WORDS * (ROUND_SIZE + 1)];
    uint32 key_dec[BLOCK_WORDS * (ROUND_SIZE + 1)];

    void key_expansion();

    virtual void encrypt_block(uchar input[BLOCK_STATES], uchar output[BLOCK_STATES]);

    void inv_multiplication(uchar state[BLOCK_STATES]);
    virtual void decrypt_block(uchar input[BLOCK_STATES], uchar output[BLOCK_STATES]);

public:
    AES128_Serial_Fast(std::string key);
};

#endif
