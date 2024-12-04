/*
Author: Qiuhong Chen
Date Created: 2024/11/4
*/

#ifndef __AES_PARALLEL_H__
#define __AES_PARALLEL_H__
#include "AES128.h"

// #define debug
#define ROUND_SIZE 10   // 10 rounds of encryption
#define BLOCK_STATES 16 // 16 bytes in a block
#define BLOCK_WORDS 4   // or 4 words in a block
#define THREAD_BLOCKS 4 // number of blocks processed by each thread

class AES128_Parallel
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

public:
    void encrypt(int threads, int round_key_position, uchar input[], uchar output[], int len);
};

#endif
