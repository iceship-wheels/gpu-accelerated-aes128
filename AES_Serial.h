/*
Author: Qiuhong Chen
Date Created: 2024/11/4
*/

#include "AES128.h"

#define ROUND_SIZE 10 // 10 rounds of encryption
#define BLOCK_SIZE 16 // 16 bytes for AES128

void print_text_hex(uchar text[], uint len);

class AES128_serial
{
protected:
    uchar key[BLOCK_SIZE * (ROUND_SIZE + 1)];
    const uchar rcon[ROUND_SIZE] = {
        0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1b, 0x36};

    void key_expansion();

public:
    virtual void encrypt(uchar input[], uchar output[], int len) = 0;
    virtual void decrypt(uchar input[], uchar output[], int len) = 0;
};

class AES128_serial_standard : public AES128_serial
{
protected:
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

    void encrypt_block(uchar input[BLOCK_SIZE], uchar output[BLOCK_SIZE]);

    void aes_1_substituteBytes(uchar state[BLOCK_SIZE]);

    void aes_2_permutation(uchar state[BLOCK_SIZE]);

    void aes_3_multiplication(uchar state[BLOCK_SIZE]);

    void aes_4_addRoundKey(uchar state[BLOCK_SIZE], uint round);

    /*
    ========================decryption========================
    */

    void decrypt_block(uchar input[BLOCK_SIZE], uchar output[BLOCK_SIZE]);

    void aes_inv_1_substituteBytes(uchar state[BLOCK_SIZE]);

    void aes_inv_2_permutation(uchar state[BLOCK_SIZE]);

    void aes_inv_3_multiplication(uchar state[BLOCK_SIZE]);

public:
    AES128_serial_standard(std::string key);

    virtual void encrypt(uchar input[], uchar output[], int len);

    virtual void decrypt(uchar input[], uchar output[], int len);
};
