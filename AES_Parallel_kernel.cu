/*
Author: Qiuhong Chen
Date Created: 2024/11/4
*/

#include <stdio.h>
#include "AES_Parallel.h"
#define BLOCK_WORDS 4 // 4 words in a block

__device__ void encrypt_block(char *input, char *output)
{
    for (int i = 0; i < BLOCK_WORDS * 4; i++)
    {
        output[i] = input[i];
    }
}

__global__ void encrypt(char *input, char *output, int blocks_per_thread, int block_num)
{
    // global id
    int gid = blockIdx.x * (blockDim.x * blockDim.y) + threadIdx.y * blockDim.x + threadIdx.x;

    // one thread handle multiple blocks
    int start_block = gid * blocks_per_thread;
    int end_block = start_block + blocks_per_thread > block_num ? block_num : start_block + blocks_per_thread;

    for (int i = start_block; i < end_block; i++)
    {
        encrypt_block(input + i * BLOCK_WORDS * 4, output + i * BLOCK_WORDS * 4);
    }
}

/*
Wrapper function for kernal launch
*/
void AES128_Parallel::encrypt(int threads, int round_key_position, char *input, char *output, int len)
{
    if (len % BLOCK_STATES != 0)
    {
        std::cerr << "[Error] Input size must be multiple of " << BLOCK_STATES << " bytes" << std::endl;
        exit(1);
    }

    int block_num = len / (BLOCK_WORDs * 4);
    int blocks_per_thread = (block_num + threads - 1) / threads;
    dim3 dimBlock(32, 32, 1);
    dim3 dimGrid((threads + 1023) / 1024, 1, 1);

    encrypt<<<dimGrid, dimBlock>>>(input, output, blocks_per_thread, block_num);
}