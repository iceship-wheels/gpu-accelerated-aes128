/*
Author: Qiuhong Chen
Date Created: 2024/11/4
*/

#include <stdio.h>
#include <iostream>
#include "AES_Parallel.h"
#define BLOCK_WORDS 4 // 4 words in a block

__device__ void print_word_hex(int *text, int len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02x %02x %02x %02x ", (int)((text[i] >> 24) & 0xff), (int)((text[i] >> 16) & 0xff), (int)((text[i] >> 8) & 0xff), (int)(text[i] & 0xff));
    }
    printf("\n");
}

__device__ void encrypt_block(int *input, int *output, int *key, int *T0, int *T1, int *T2, int *T3, unsigned char *sbox)
{
    int w[BLOCK_WORDS];
    int w_new[BLOCK_WORDS];

    // get words from input
    w[0] = ((input[0] >> 24) & 0xff) | (((input[0] >> 16) & 0xff) << 8) | (((input[0] >> 8) & 0xff) << 16) | ((input[0] & 0xff) << 24);
    w[1] = ((input[1] >> 24) & 0xff) | (((input[1] >> 16) & 0xff) << 8) | (((input[1] >> 8) & 0xff) << 16) | ((input[1] & 0xff) << 24);
    w[2] = ((input[2] >> 24) & 0xff) | (((input[2] >> 16) & 0xff) << 8) | (((input[2] >> 8) & 0xff) << 16) | ((input[2] & 0xff) << 24);
    w[3] = ((input[3] >> 24) & 0xff) | (((input[3] >> 16) & 0xff) << 8) | (((input[3] >> 8) & 0xff) << 16) | ((input[3] & 0xff) << 24);

    // round 0
    w[0] ^= key[0];
    w[1] ^= key[1];
    w[2] ^= key[2];
    w[3] ^= key[3];
#ifdef debug
    printf("Round 0: ");
    print_word_hex(w, BLOCK_WORDS);
#endif

    // round 1 to ROUND_SIZE-1
    for (int r = 1; r < ROUND_SIZE; r++)
    {
        w_new[0] = T0[(w[0] >> 24) & 0xff] ^ T1[(w[1] >> 16) & 0xff] ^ T2[(w[2] >> 8) & 0xff] ^ T3[w[3] & 0xff] ^ key[r * 4];
        w_new[1] = T0[(w[1] >> 24) & 0xff] ^ T1[(w[2] >> 16) & 0xff] ^ T2[(w[3] >> 8) & 0xff] ^ T3[w[0] & 0xff] ^ key[r * 4 + 1];
        w_new[2] = T0[(w[2] >> 24) & 0xff] ^ T1[(w[3] >> 16) & 0xff] ^ T2[(w[0] >> 8) & 0xff] ^ T3[w[1] & 0xff] ^ key[r * 4 + 2];
        w_new[3] = T0[(w[3] >> 24) & 0xff] ^ T1[(w[0] >> 16) & 0xff] ^ T2[(w[1] >> 8) & 0xff] ^ T3[w[2] & 0xff] ^ key[r * 4 + 3];
        for (int i = 0; i < BLOCK_WORDS; ++i)
        {
            w[i] = w_new[i];
        }
#ifdef debug
        printf("Round %d: ", r);
        print_word_hex(w, BLOCK_WORDS);
#endif
    }
    // round ROUND_SIZE: substituteBytes, shiftRows, addRoundKey (no mixColumns)
    w_new[0] = (sbox[(w[0] >> 24) & 0xff] << 24) ^ (sbox[(w[1] >> 16) & 0xff] << 16) ^ (sbox[(w[2] >> 8) & 0xff] << 8) ^ sbox[w[3] & 0xff] ^ key[ROUND_SIZE * 4];
    w_new[1] = (sbox[(w[1] >> 24) & 0xff] << 24) ^ (sbox[(w[2] >> 16) & 0xff] << 16) ^ (sbox[(w[3] >> 8) & 0xff] << 8) ^ sbox[w[0] & 0xff] ^ key[ROUND_SIZE * 4 + 1];
    w_new[2] = (sbox[(w[2] >> 24) & 0xff] << 24) ^ (sbox[(w[3] >> 16) & 0xff] << 16) ^ (sbox[(w[0] >> 8) & 0xff] << 8) ^ sbox[w[1] & 0xff] ^ key[ROUND_SIZE * 4 + 2];
    w_new[3] = (sbox[(w[3] >> 24) & 0xff] << 24) ^ (sbox[(w[0] >> 16) & 0xff] << 16) ^ (sbox[(w[1] >> 8) & 0xff] << 8) ^ sbox[w[2] & 0xff] ^ key[ROUND_SIZE * 4 + 3];
#ifdef debug
    printf("Round %d: ", ROUND_SIZE);
    print_word_hex(key + ROUND_SIZE * 4, BLOCK_WORDS);
    print_word_hex(w_new, BLOCK_WORDS);
#endif

    // get output
    output[0] = ((w_new[0] >> 24) & 0xff) | (((w_new[0] >> 16) & 0xff) << 8) | (((w_new[0] >> 8) & 0xff) << 16) | ((w_new[0] & 0xff) << 24);
    output[1] = ((w_new[1] >> 24) & 0xff) | (((w_new[1] >> 16) & 0xff) << 8) | (((w_new[1] >> 8) & 0xff) << 16) | ((w_new[1] & 0xff) << 24);
    output[2] = ((w_new[2] >> 24) & 0xff) | (((w_new[2] >> 16) & 0xff) << 8) | (((w_new[2] >> 8) & 0xff) << 16) | ((w_new[2] & 0xff) << 24);
    output[3] = ((w_new[3] >> 24) & 0xff) | (((w_new[3] >> 16) & 0xff) << 8) | (((w_new[3] >> 8) & 0xff) << 16) | ((w_new[3] & 0xff) << 24);
    print_word_hex(output, BLOCK_WORDS);
}

__global__ void encrypt_kernel(int *input, int *output, int blocks_per_thread, int block_num, int *key, int *T0, int *T1, int *T2, int *T3, unsigned char *sbox)
{
    // global id
    int gid = blockIdx.x * (blockDim.x * blockDim.y) + threadIdx.y * blockDim.x + threadIdx.x;

    // one thread handle multiple blocks
    int start_block = gid * blocks_per_thread;
    int end_block = start_block + blocks_per_thread > block_num ? block_num : start_block + blocks_per_thread;

    // T-table: 3*256*4 bytes, store in shared memory
    // key: 44*4 bytes, store in register file
    // sbox: 256 bytes, store in register file
    for (int i = start_block; i < end_block; i++)
    {
        printf("Thread %d, block %d\n", gid, i);
        encrypt_block(input + i * BLOCK_WORDS, output + i * BLOCK_WORDS, key, T0, T1, T2, T3, sbox);
    }
}

/*
Wrapper function for kernal launch
*/
void AES128_Parallel::encrypt(int threads, int round_key_position, uchar input[], uchar output[], int len)
{
    if (len % BLOCK_STATES != 0)
    {
        std::cerr << "[Error] Input size must be multiple of " << BLOCK_STATES << " bytes" << std::endl;
        exit(1);
    }

    int block_num = len / (BLOCK_WORDS * 4);
    int blocks_per_thread = (block_num + threads - 1) / threads;
    printf("Kernel launcher: %d bytes, %d blocks, %d threads, %d blocks per thread\n", len, block_num, threads, blocks_per_thread);
    dim3 dimBlock(32, 32, 1);
    dim3 dimGrid((threads + 1023) / 1024, 1, 1);

    // T-table and round key
    int *T0_d, *T1_d, *T2_d, *T3_d;
    cudaMalloc((int **)&T0_d, sizeof(T0));
    cudaMalloc((int **)&T1_d, sizeof(T1));
    cudaMalloc((int **)&T2_d, sizeof(T2));
    cudaMalloc((int **)&T3_d, sizeof(T3));
    cudaMemcpy(T0_d, T0, sizeof(T0), cudaMemcpyHostToDevice);
    cudaMemcpy(T1_d, T1, sizeof(T1), cudaMemcpyHostToDevice);
    cudaMemcpy(T2_d, T2, sizeof(T2), cudaMemcpyHostToDevice);
    cudaMemcpy(T3_d, T3, sizeof(T3), cudaMemcpyHostToDevice);

    // round keys
    int *key_d;
    cudaMalloc((int **)&key_d, sizeof(key));
    cudaMemcpy(key_d, key, sizeof(key), cudaMemcpyHostToDevice);

    // s-bodx
    unsigned char *sbox_d;
    cudaMalloc((unsigned char **)&sbox_d, sizeof(sbox));
    cudaMemcpy(sbox_d, sbox, sizeof(sbox), cudaMemcpyHostToDevice);

    // input and output
    int *x_h, *y_h, *x_d, *y_d;
    x_h = reinterpret_cast<int *>(input); // caution: x86 and arm both use little endian
    y_h = reinterpret_cast<int *>(output);
    cudaMalloc((int **)&x_d, len);
    cudaMalloc((int **)&y_d, len);
    cudaMemcpy(x_d, x_h, len, cudaMemcpyHostToDevice);
    // std::cout << (x_h[0] >> 24) << std::endl;
    // std::cout << int(input[3]) << std::endl;

    encrypt_kernel<<<dimGrid, dimBlock>>>(x_d, y_d, blocks_per_thread, block_num, key_d, T0_d, T1_d, T2_d, T3_d, sbox_d);

    cudaMemcpy(y_h, y_d, len, cudaMemcpyDeviceToHost);
}
