/*
Author: Qiuhong Chen
Date Created: 2024/11/4
*/

#include <stdio.h>
#include <iostream>
#include "AES_Parallel.h"
#define BLOCK_WORDS 4 // 4 words in a block

__device__ void print_word_hex_device(int *text, int len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02x %02x %02x %02x ", (int)((text[i] >> 24) & 0xff), (int)((text[i] >> 16) & 0xff), (int)((text[i] >> 8) & 0xff), (int)(text[i] & 0xff));
    }
    printf("\n");
}

/*
Constant data
*/
__constant__ int T0_const[256];
__constant__ int T1_const[256];
__constant__ int T2_const[256];
__constant__ int T3_const[256];
__constant__ uchar sbox_const[256];
__constant__ int key_const[44 * 4];

#pragma region Encryption

__device__ void encrypt_block(int *input, int *output, int *key, int *T0, int *T1, int *T2, int *T3, uchar *sbox)
{
#ifdef debug
    printf("----Encryption----\n");
#endif

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
    print_word_hex_device(w, BLOCK_WORDS);
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
        print_word_hex_device(w, BLOCK_WORDS);
#endif
    }
    // round ROUND_SIZE: substituteBytes, shiftRows, addRoundKey (no mixColumns)
    w_new[0] = (sbox[(w[0] >> 24) & 0xff] << 24) ^ (sbox[(w[1] >> 16) & 0xff] << 16) ^ (sbox[(w[2] >> 8) & 0xff] << 8) ^ sbox[w[3] & 0xff] ^ key[ROUND_SIZE * 4];
    w_new[1] = (sbox[(w[1] >> 24) & 0xff] << 24) ^ (sbox[(w[2] >> 16) & 0xff] << 16) ^ (sbox[(w[3] >> 8) & 0xff] << 8) ^ sbox[w[0] & 0xff] ^ key[ROUND_SIZE * 4 + 1];
    w_new[2] = (sbox[(w[2] >> 24) & 0xff] << 24) ^ (sbox[(w[3] >> 16) & 0xff] << 16) ^ (sbox[(w[0] >> 8) & 0xff] << 8) ^ sbox[w[1] & 0xff] ^ key[ROUND_SIZE * 4 + 2];
    w_new[3] = (sbox[(w[3] >> 24) & 0xff] << 24) ^ (sbox[(w[0] >> 16) & 0xff] << 16) ^ (sbox[(w[1] >> 8) & 0xff] << 8) ^ sbox[w[2] & 0xff] ^ key[ROUND_SIZE * 4 + 3];
#ifdef debug
    printf("Round %d: ", ROUND_SIZE);
    print_word_hex_device(w_new, BLOCK_WORDS);
#endif

    // get output
    output[0] = ((w_new[0] >> 24) & 0xff) | (((w_new[0] >> 16) & 0xff) << 8) | (((w_new[0] >> 8) & 0xff) << 16) | ((w_new[0] & 0xff) << 24);
    output[1] = ((w_new[1] >> 24) & 0xff) | (((w_new[1] >> 16) & 0xff) << 8) | (((w_new[1] >> 8) & 0xff) << 16) | ((w_new[1] & 0xff) << 24);
    output[2] = ((w_new[2] >> 24) & 0xff) | (((w_new[2] >> 16) & 0xff) << 8) | (((w_new[2] >> 8) & 0xff) << 16) | ((w_new[2] & 0xff) << 24);
    output[3] = ((w_new[3] >> 24) & 0xff) | (((w_new[3] >> 16) & 0xff) << 8) | (((w_new[3] >> 8) & 0xff) << 16) | ((w_new[3] & 0xff) << 24);
}

__device__ void encrypt_block_warp_shuffle(int *input, int *output, int *T0, int *T1, int *T2, int *T3, uchar *sbox, int *key_0, int *key_1, int *key_2, int *key_3)
{
#ifdef debug
    if (input != output)
    {
        printf("----Encryption----\n");
    }
#endif

    int w[BLOCK_WORDS];
    int w_new[BLOCK_WORDS];

    // get words from input

    w[0] = ((input[0] >> 24) & 0xff) | (((input[0] >> 16) & 0xff) << 8) | (((input[0] >> 8) & 0xff) << 16) | ((input[0] & 0xff) << 24);
    w[1] = ((input[1] >> 24) & 0xff) | (((input[1] >> 16) & 0xff) << 8) | (((input[1] >> 8) & 0xff) << 16) | ((input[1] & 0xff) << 24);
    w[2] = ((input[2] >> 24) & 0xff) | (((input[2] >> 16) & 0xff) << 8) | (((input[2] >> 8) & 0xff) << 16) | ((input[2] & 0xff) << 24);
    w[3] = ((input[3] >> 24) & 0xff) | (((input[3] >> 16) & 0xff) << 8) | (((input[3] >> 8) & 0xff) << 16) | ((input[3] & 0xff) << 24);

    // round 0
    w[0] ^= __shfl_sync(0xffffffff, *key_0, 0);
    w[1] ^= __shfl_sync(0xffffffff, *key_1, 0);
    w[2] ^= __shfl_sync(0xffffffff, *key_2, 0);
    w[3] ^= __shfl_sync(0xffffffff, *key_3, 0);
#ifdef debug
    if (input != output)
    {
        printf("Round 0: ");
        print_word_hex_device(w, BLOCK_WORDS);
    }
#endif

    // round 1 to ROUND_SIZE-1
    for (int r = 1; r < ROUND_SIZE; r++)
    {
        w_new[0] = T0[(w[0] >> 24) & 0xff] ^ T1[(w[1] >> 16) & 0xff] ^ T2[(w[2] >> 8) & 0xff] ^ T3[w[3] & 0xff] ^ __shfl_sync(0xffffffff, *key_0, r);
        w_new[1] = T0[(w[1] >> 24) & 0xff] ^ T1[(w[2] >> 16) & 0xff] ^ T2[(w[3] >> 8) & 0xff] ^ T3[w[0] & 0xff] ^ __shfl_sync(0xffffffff, *key_1, r);
        w_new[2] = T0[(w[2] >> 24) & 0xff] ^ T1[(w[3] >> 16) & 0xff] ^ T2[(w[0] >> 8) & 0xff] ^ T3[w[1] & 0xff] ^ __shfl_sync(0xffffffff, *key_2, r);
        w_new[3] = T0[(w[3] >> 24) & 0xff] ^ T1[(w[0] >> 16) & 0xff] ^ T2[(w[1] >> 8) & 0xff] ^ T3[w[2] & 0xff] ^ __shfl_sync(0xffffffff, *key_3, r);
        for (int i = 0; i < BLOCK_WORDS; ++i)
        {
            w[i] = w_new[i];
        }
#ifdef debug
        if (input != output)
        {
            printf("Round %d: ", r);
            print_word_hex_device(w, BLOCK_WORDS);
        }
#endif
    }
    // round ROUND_SIZE: substituteBytes, shiftRows, addRoundKey (no mixColumns)
    w_new[0] = (sbox[(w[0] >> 24) & 0xff] << 24) ^ (sbox[(w[1] >> 16) & 0xff] << 16) ^ (sbox[(w[2] >> 8) & 0xff] << 8) ^ sbox[w[3] & 0xff] ^ __shfl_sync(0xffffffff, *key_0, ROUND_SIZE);
    w_new[1] = (sbox[(w[1] >> 24) & 0xff] << 24) ^ (sbox[(w[2] >> 16) & 0xff] << 16) ^ (sbox[(w[3] >> 8) & 0xff] << 8) ^ sbox[w[0] & 0xff] ^ __shfl_sync(0xffffffff, *key_1, ROUND_SIZE);
    w_new[2] = (sbox[(w[2] >> 24) & 0xff] << 24) ^ (sbox[(w[3] >> 16) & 0xff] << 16) ^ (sbox[(w[0] >> 8) & 0xff] << 8) ^ sbox[w[1] & 0xff] ^ __shfl_sync(0xffffffff, *key_2, ROUND_SIZE);
    w_new[3] = (sbox[(w[3] >> 24) & 0xff] << 24) ^ (sbox[(w[0] >> 16) & 0xff] << 16) ^ (sbox[(w[1] >> 8) & 0xff] << 8) ^ sbox[w[2] & 0xff] ^ __shfl_sync(0xffffffff, *key_3, ROUND_SIZE);
#ifdef debug
    if (input != output)
    {
        printf("Round %d: ", ROUND_SIZE);
        print_word_hex_device(w_new, BLOCK_WORDS);
    }
#endif

    // get output
    output[0] = ((w_new[0] >> 24) & 0xff) | (((w_new[0] >> 16) & 0xff) << 8) | (((w_new[0] >> 8) & 0xff) << 16) | ((w_new[0] & 0xff) << 24);
    output[1] = ((w_new[1] >> 24) & 0xff) | (((w_new[1] >> 16) & 0xff) << 8) | (((w_new[1] >> 8) & 0xff) << 16) | ((w_new[1] & 0xff) << 24);
    output[2] = ((w_new[2] >> 24) & 0xff) | (((w_new[2] >> 16) & 0xff) << 8) | (((w_new[2] >> 8) & 0xff) << 16) | ((w_new[2] & 0xff) << 24);
    output[3] = ((w_new[3] >> 24) & 0xff) | (((w_new[3] >> 16) & 0xff) << 8) | (((w_new[3] >> 8) & 0xff) << 16) | ((w_new[3] & 0xff) << 24);
}

#pragma region Encryption kernels

/*
ALL_CONSTANT
T-table: 4*256*4 bytes, constant memory
key: 44*4 bytes, constant memory
sbox: 256 bytes, constant memory
*/
__global__ void encrypt_kernel_1(int *input, int *output, int blocks_per_thread, int block_num)
{
    // global id
    int gid = blockIdx.x * (blockDim.x * blockDim.y) + threadIdx.y * blockDim.x + threadIdx.x;

    // one thread handle multiple blocks
    int start_block = gid * blocks_per_thread;
    int end_block = start_block + blocks_per_thread > block_num ? block_num : start_block + blocks_per_thread;

    for (int i = start_block; i < end_block; i++)
    {
        encrypt_block(input + i * BLOCK_WORDS, output + i * BLOCK_WORDS, key_const, T0_const, T1_const, T2_const, T3_const, sbox_const);
    }
}

/*
ALL_SHARED
T-table: 4*256*4 bytes, shared memory
key: 44*4 bytes, shared memory
sbox: 256 bytes, shared memory
*/
__global__ void encrypt_kernel_2(int *input, int *output, int blocks_per_thread, int block_num)
{
    // global id
    int tid = threadIdx.y * blockDim.x + threadIdx.x;
    int gid = blockIdx.x * (blockDim.x * blockDim.y) + tid;

    // shared memory
    __shared__ int key_shared[44 * 4];
    __shared__ int T0_shared[256];
    __shared__ int T1_shared[256];
    __shared__ int T2_shared[256];
    __shared__ int T3_shared[256];
    __shared__ uchar sbox_shared[256];

    if (tid < 44 * 4)
    {
        key_shared[tid] = key_const[tid];
    }

    if (tid < 256)
    {
        T0_shared[tid] = T0_const[tid];
        T1_shared[tid] = T1_const[tid];
        T2_shared[tid] = T2_const[tid];
        T3_shared[tid] = T3_const[tid];
        sbox_shared[tid] = sbox_const[tid];
    }
    __syncthreads();

    // one thread handle multiple blocks
    int start_block = gid * blocks_per_thread;
    int end_block = start_block + blocks_per_thread > block_num ? block_num : start_block + blocks_per_thread;

    for (int i = start_block; i < end_block; i++)
    {
        encrypt_block(input + i * BLOCK_WORDS, output + i * BLOCK_WORDS, key_shared, T0_shared, T1_shared, T2_shared, T3_shared, sbox_shared);
    }
}

/*
WARP_SHUFFLE
T-table: 4*256*4 bytes, shared memory
key: 44*4 bytes, register file
sbox: 256 bytes, shared memory
*/
__global__ void encrypt_kernel_3(int *input, int *output, int blocks_per_thread, int block_num)
{
    // global id
    int tid = threadIdx.y * blockDim.x + threadIdx.x;
    int gid = blockIdx.x * (blockDim.x * blockDim.y) + tid;

    // register file
    int key_local_0, key_local_1, key_local_2, key_local_3;
    if (tid % 32 <= ROUND_SIZE)
    {
        key_local_0 = key_const[(tid % 32) * 4];
        key_local_1 = key_const[(tid % 32) * 4 + 1];
        key_local_2 = key_const[(tid % 32) * 4 + 2];
        key_local_3 = key_const[(tid % 32) * 4 + 3];
    }

    // shared memory
    __shared__ int T0_shared[256];
    __shared__ int T1_shared[256];
    __shared__ int T2_shared[256];
    __shared__ int T3_shared[256];
    __shared__ uchar sbox_shared[256];

    if (tid < 256)
    {
        T0_shared[tid] = T0_const[tid];
        T1_shared[tid] = T1_const[tid];
        T2_shared[tid] = T2_const[tid];
        T3_shared[tid] = T3_const[tid];
        sbox_shared[tid] = sbox_const[tid];
    }
    __syncthreads();

#ifdef debug
    // warp shuffle test
    if (tid < 32)
    {
        for (int i = 0; i < ROUND_SIZE + 1; i++)
        {
            int key_test_0 = __shfl_sync(0xffffffff, key_local_0, i);
            int key_test_1 = __shfl_sync(0xffffffff, key_local_1, i);
            int key_test_2 = __shfl_sync(0xffffffff, key_local_2, i);
            int key_test_3 = __shfl_sync(0xffffffff, key_local_3, i);
            if (tid == 0)
            {
                printf("%08x %08x %08x %08x\n", key_test_0, key_test_1, key_test_2, key_test_3);
            }
        }
    }
#endif

    // one thread handle multiple blocks
    int start_block = gid * blocks_per_thread;
    int end_block = start_block + blocks_per_thread > block_num ? block_num : start_block + blocks_per_thread;
    int fake_word[4];

    for (int i = start_block; i < start_block + blocks_per_thread; i++)
    {
        encrypt_block_warp_shuffle(i < end_block ? input + i * BLOCK_WORDS : fake_word, i < end_block ? output + i * BLOCK_WORDS : fake_word, T0_shared, T1_shared, T2_shared, T3_shared, sbox_shared, &key_local_0, &key_local_1, &key_local_2, &key_local_3);
    }
}

#pragma endregion

/*
Wrapper function for kernal launch
*/
METRIC AES128_Parallel::encrypt(int threads, OPTIMIZATION opt, uchar input[], uchar output[], int len)
{
    if (len % BLOCK_STATES != 0)
    {
        std::cerr << "[Error] Input size must be multiple of " << BLOCK_STATES << " bytes" << std::endl;
        exit(1);
    }

    int block_num = len / (BLOCK_WORDS * 4);
    int blocks_per_thread = (block_num + threads - 1) / threads;
    printf("Encrypt kernel launcher: %d bytes, %d cipher blocks, %d threads, %d cipher blocks per thread\n", len, block_num, threads, blocks_per_thread);
    dim3 dimBlock(512, 1, 1);
    dim3 dimGrid((threads + 511) / 512, 1, 1);

    // timing
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start);

    // T-table
    cudaMemcpyToSymbol(T0_const, T0, sizeof(T0));
    cudaMemcpyToSymbol(T1_const, T1, sizeof(T1));
    cudaMemcpyToSymbol(T2_const, T2, sizeof(T2));
    cudaMemcpyToSymbol(T3_const, T3, sizeof(T3));

    // round keys
    cudaMemcpyToSymbol(key_const, key, sizeof(key));

    // s-box
    cudaMemcpyToSymbol(sbox_const, sbox, sizeof(sbox));

    // input and output
    int *x_h, *y_h, *x_d, *y_d;
    x_h = reinterpret_cast<int *>(input); // caution: x86 and arm both use little endian
    y_h = reinterpret_cast<int *>(output);
    cudaMalloc((int **)&x_d, len);
    cudaMalloc((int **)&y_d, len);
    cudaMemcpy(x_d, x_h, len, cudaMemcpyHostToDevice);
    // std::cout << (x_h[0] >> 24) << std::endl;
    // std::cout << int(input[3]) << std::endl;

    switch (opt)
    {
    case ALL_CONSTANT:
        encrypt_kernel_1<<<dimGrid, dimBlock>>>(x_d, y_d, blocks_per_thread, block_num);
        break;
    case ALL_SHARED:
        encrypt_kernel_2<<<dimGrid, dimBlock>>>(x_d, y_d, blocks_per_thread, block_num);
        break;
    case WARP_SHUFFLE:
        encrypt_kernel_3<<<dimGrid, dimBlock>>>(x_d, y_d, blocks_per_thread, block_num);
        break;
    default:
        std::cerr << "[Error] Invalid optimization option" << std::endl;
        break;
    }

    cudaMemcpy(y_h, y_d, len, cudaMemcpyDeviceToHost);

    // timing
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    float milliseconds = 0;
    cudaEventElapsedTime(&milliseconds, start, stop);
    return METRIC{milliseconds};
}

#pragma endregion

#pragma region Decryption

__device__ void decrypt_block(int *input, int *output, int *key_dec, int *inv_T0, int *inv_T1, int *inv_T2, int *inv_T3, uchar *inv_sbox)
{
#ifdef debug
    printf("----Decryption----\n");
#endif

    int w[BLOCK_WORDS];
    int w_new[BLOCK_WORDS];

    // get words from input
    w[0] = ((input[0] >> 24) & 0xff) | (((input[0] >> 16) & 0xff) << 8) | (((input[0] >> 8) & 0xff) << 16) | ((input[0] & 0xff) << 24);
    w[1] = ((input[1] >> 24) & 0xff) | (((input[1] >> 16) & 0xff) << 8) | (((input[1] >> 8) & 0xff) << 16) | ((input[1] & 0xff) << 24);
    w[2] = ((input[2] >> 24) & 0xff) | (((input[2] >> 16) & 0xff) << 8) | (((input[2] >> 8) & 0xff) << 16) | ((input[2] & 0xff) << 24);
    w[3] = ((input[3] >> 24) & 0xff) | (((input[3] >> 16) & 0xff) << 8) | (((input[3] >> 8) & 0xff) << 16) | ((input[3] & 0xff) << 24);

    // round ROUND_SIZE
    w[0] ^= key_dec[ROUND_SIZE * 4];
    w[1] ^= key_dec[ROUND_SIZE * 4 + 1];
    w[2] ^= key_dec[ROUND_SIZE * 4 + 2];
    w[3] ^= key_dec[ROUND_SIZE * 4 + 3];
#ifdef debug
    printf("Round %d: ", ROUND_SIZE);
    print_word_hex_device(w, BLOCK_WORDS);
#endif
    // round ROUND_SIZE-1 to 1
    for (int r = ROUND_SIZE - 1; r > 0; r--)
    {
        w_new[0] = inv_T0[(w[0] >> 24) & 0xff] ^ inv_T1[(w[3] >> 16) & 0xff] ^ inv_T2[(w[2] >> 8) & 0xff] ^ inv_T3[w[1] & 0xff] ^ key_dec[r * 4];
        w_new[1] = inv_T0[(w[1] >> 24) & 0xff] ^ inv_T1[(w[0] >> 16) & 0xff] ^ inv_T2[(w[3] >> 8) & 0xff] ^ inv_T3[w[2] & 0xff] ^ key_dec[r * 4 + 1];
        w_new[2] = inv_T0[(w[2] >> 24) & 0xff] ^ inv_T1[(w[1] >> 16) & 0xff] ^ inv_T2[(w[0] >> 8) & 0xff] ^ inv_T3[w[3] & 0xff] ^ key_dec[r * 4 + 2];
        w_new[3] = inv_T0[(w[3] >> 24) & 0xff] ^ inv_T1[(w[2] >> 16) & 0xff] ^ inv_T2[(w[1] >> 8) & 0xff] ^ inv_T3[w[0] & 0xff] ^ key_dec[r * 4 + 3];
        for (int i = 0; i < BLOCK_WORDS; ++i)
        {
            w[i] = w_new[i];
        }
#ifdef debug
        printf("Round %d: ", r);
        print_word_hex_device(w, BLOCK_WORDS);
#endif
    }

    // round 0: substituteBytes, shiftRows, addRoundKey
    w_new[0] = (inv_sbox[(w[0] >> 24) & 0xff] << 24) ^ (inv_sbox[(w[3] >> 16) & 0xff] << 16) ^ (inv_sbox[(w[2] >> 8) & 0xff] << 8) ^ inv_sbox[w[1] & 0xff] ^ key_dec[0];
    w_new[1] = (inv_sbox[(w[1] >> 24) & 0xff] << 24) ^ (inv_sbox[(w[0] >> 16) & 0xff] << 16) ^ (inv_sbox[(w[3] >> 8) & 0xff] << 8) ^ inv_sbox[w[2] & 0xff] ^ key_dec[1];
    w_new[2] = (inv_sbox[(w[2] >> 24) & 0xff] << 24) ^ (inv_sbox[(w[1] >> 16) & 0xff] << 16) ^ (inv_sbox[(w[0] >> 8) & 0xff] << 8) ^ inv_sbox[w[3] & 0xff] ^ key_dec[2];
    w_new[3] = (inv_sbox[(w[3] >> 24) & 0xff] << 24) ^ (inv_sbox[(w[2] >> 16) & 0xff] << 16) ^ (inv_sbox[(w[1] >> 8) & 0xff] << 8) ^ inv_sbox[w[0] & 0xff] ^ key_dec[3];
#ifdef debug
    printf("Round 0: ");
    print_word_hex_device(w_new, BLOCK_WORDS);
#endif

    // get output
    output[0] = ((w_new[0] >> 24) & 0xff) | (((w_new[0] >> 16) & 0xff) << 8) | (((w_new[0] >> 8) & 0xff) << 16) | ((w_new[0] & 0xff) << 24);
    output[1] = ((w_new[1] >> 24) & 0xff) | (((w_new[1] >> 16) & 0xff) << 8) | (((w_new[1] >> 8) & 0xff) << 16) | ((w_new[1] & 0xff) << 24);
    output[2] = ((w_new[2] >> 24) & 0xff) | (((w_new[2] >> 16) & 0xff) << 8) | (((w_new[2] >> 8) & 0xff) << 16) | ((w_new[2] & 0xff) << 24);
    output[3] = ((w_new[3] >> 24) & 0xff) | (((w_new[3] >> 16) & 0xff) << 8) | (((w_new[3] >> 8) & 0xff) << 16) | ((w_new[3] & 0xff) << 24);
}

__device__ void decrypt_block_warp_shuffle(int *input, int *output, int *inv_T0, int *inv_T1, int *inv_T2, int *inv_T3, uchar *inv_sbox, int *key_dec_0, int *key_dec_1, int *key_dec_2, int *key_dec_3)
{
#ifdef debug
    if (input != output)
    {
        printf("----Decryption----\n");
    }
#endif

    int w[BLOCK_WORDS];
    int w_new[BLOCK_WORDS];

    // get words from input
    w[0] = ((input[0] >> 24) & 0xff) | (((input[0] >> 16) & 0xff) << 8) | (((input[0] >> 8) & 0xff) << 16) | ((input[0] & 0xff) << 24);
    w[1] = ((input[1] >> 24) & 0xff) | (((input[1] >> 16) & 0xff) << 8) | (((input[1] >> 8) & 0xff) << 16) | ((input[1] & 0xff) << 24);
    w[2] = ((input[2] >> 24) & 0xff) | (((input[2] >> 16) & 0xff) << 8) | (((input[2] >> 8) & 0xff) << 16) | ((input[2] & 0xff) << 24);
    w[3] = ((input[3] >> 24) & 0xff) | (((input[3] >> 16) & 0xff) << 8) | (((input[3] >> 8) & 0xff) << 16) | ((input[3] & 0xff) << 24);

    // round ROUND_SIZE
    w[0] ^= __shfl_sync(0xffffffff, *key_dec_0, ROUND_SIZE);
    w[1] ^= __shfl_sync(0xffffffff, *key_dec_1, ROUND_SIZE);
    w[2] ^= __shfl_sync(0xffffffff, *key_dec_2, ROUND_SIZE);
    w[3] ^= __shfl_sync(0xffffffff, *key_dec_3, ROUND_SIZE);

#ifdef debug
    if (input != output)
    {
        printf("Round %d: ", ROUND_SIZE);
        print_word_hex_device(w, BLOCK_WORDS);
    }
#endif
    // round ROUND_SIZE-1 to 1
    for (int r = ROUND_SIZE - 1; r > 0; r--)
    {
        w_new[0] = inv_T0[(w[0] >> 24) & 0xff] ^ inv_T1[(w[3] >> 16) & 0xff] ^ inv_T2[(w[2] >> 8) & 0xff] ^ inv_T3[w[1] & 0xff] ^ __shfl_sync(0xffffffff, *key_dec_0, r);
        w_new[1] = inv_T0[(w[1] >> 24) & 0xff] ^ inv_T1[(w[0] >> 16) & 0xff] ^ inv_T2[(w[3] >> 8) & 0xff] ^ inv_T3[w[2] & 0xff] ^ __shfl_sync(0xffffffff, *key_dec_1, r);
        w_new[2] = inv_T0[(w[2] >> 24) & 0xff] ^ inv_T1[(w[1] >> 16) & 0xff] ^ inv_T2[(w[0] >> 8) & 0xff] ^ inv_T3[w[3] & 0xff] ^ __shfl_sync(0xffffffff, *key_dec_2, r);
        w_new[3] = inv_T0[(w[3] >> 24) & 0xff] ^ inv_T1[(w[2] >> 16) & 0xff] ^ inv_T2[(w[1] >> 8) & 0xff] ^ inv_T3[w[0] & 0xff] ^ __shfl_sync(0xffffffff, *key_dec_3, r);
        for (int i = 0; i < BLOCK_WORDS; ++i)
        {
            w[i] = w_new[i];
        }
#ifdef debug
        if (input != output)
        {
            printf("Round %d: ", r);
            print_word_hex_device(w, BLOCK_WORDS);
        }
#endif
    }

    // round 0: substituteBytes, shiftRows, addRoundKey
    w_new[0] = (inv_sbox[(w[0] >> 24) & 0xff] << 24) ^ (inv_sbox[(w[3] >> 16) & 0xff] << 16) ^ (inv_sbox[(w[2] >> 8) & 0xff] << 8) ^ inv_sbox[w[1] & 0xff] ^ __shfl_sync(0xffffffff, *key_dec_0, 0);
    w_new[1] = (inv_sbox[(w[1] >> 24) & 0xff] << 24) ^ (inv_sbox[(w[0] >> 16) & 0xff] << 16) ^ (inv_sbox[(w[3] >> 8) & 0xff] << 8) ^ inv_sbox[w[2] & 0xff] ^ __shfl_sync(0xffffffff, *key_dec_1, 0);
    w_new[2] = (inv_sbox[(w[2] >> 24) & 0xff] << 24) ^ (inv_sbox[(w[1] >> 16) & 0xff] << 16) ^ (inv_sbox[(w[0] >> 8) & 0xff] << 8) ^ inv_sbox[w[3] & 0xff] ^ __shfl_sync(0xffffffff, *key_dec_2, 0);
    w_new[3] = (inv_sbox[(w[3] >> 24) & 0xff] << 24) ^ (inv_sbox[(w[2] >> 16) & 0xff] << 16) ^ (inv_sbox[(w[1] >> 8) & 0xff] << 8) ^ inv_sbox[w[0] & 0xff] ^ __shfl_sync(0xffffffff, *key_dec_3, 0);
#ifdef debug
    if (input != output)
    {
        printf("Round 0: ");
        print_word_hex_device(w_new, BLOCK_WORDS);
    }
#endif

    // get output
    output[0] = ((w_new[0] >> 24) & 0xff) | (((w_new[0] >> 16) & 0xff) << 8) | (((w_new[0] >> 8) & 0xff) << 16) | ((w_new[0] & 0xff) << 24);
    output[1] = ((w_new[1] >> 24) & 0xff) | (((w_new[1] >> 16) & 0xff) << 8) | (((w_new[1] >> 8) & 0xff) << 16) | ((w_new[1] & 0xff) << 24);
    output[2] = ((w_new[2] >> 24) & 0xff) | (((w_new[2] >> 16) & 0xff) << 8) | (((w_new[2] >> 8) & 0xff) << 16) | ((w_new[2] & 0xff) << 24);
    output[3] = ((w_new[3] >> 24) & 0xff) | (((w_new[3] >> 16) & 0xff) << 8) | (((w_new[3] >> 8) & 0xff) << 16) | ((w_new[3] & 0xff) << 24);
}

#pragma region Decryption kernels

/*
ALL_CONSTANT
T-table: 4*256*4 bytes, constant memory
key: 44*4 bytes, constant memory
sbox: 256 bytes, constant memory
*/
__global__ void decrypt_kernel_all_global(int *input, int *output, int blocks_per_thread, int block_num)
{
    // global id
    int gid = blockIdx.x * (blockDim.x * blockDim.y) + threadIdx.y * blockDim.x + threadIdx.x;

    // one thread handle multiple blocks
    int start_block = gid * blocks_per_thread;
    int end_block = start_block + blocks_per_thread > block_num ? block_num : start_block + blocks_per_thread;

    for (int i = start_block; i < end_block; i++)
    {
        decrypt_block(input + i * BLOCK_WORDS, output + i * BLOCK_WORDS, key_const, T0_const, T1_const, T2_const, T3_const, sbox_const);
    }
}

/*
ALL_SHARED
T-table: 4*256*4 bytes, shared memory
key: 44*4 bytes, shared memory
sbox: 256 bytes, shared memory
*/
__global__ void decrypt_kernel_all_shared(int *input, int *output, int blocks_per_thread, int block_num)
{
    // global id
    int tid = threadIdx.y * blockDim.x + threadIdx.x;
    int gid = blockIdx.x * (blockDim.x * blockDim.y) + tid;

    // shared memory
    __shared__ int key_shared[44 * 4];
    __shared__ int T0_shared[256];
    __shared__ int T1_shared[256];
    __shared__ int T2_shared[256];
    __shared__ int T3_shared[256];
    __shared__ uchar sbox_shared[256];

    if (tid < 44 * 4)
    {
        key_shared[tid] = key_const[tid];
    }

    if (tid < 256)
    {
        T0_shared[tid] = T0_const[tid];
        T1_shared[tid] = T1_const[tid];
        T2_shared[tid] = T2_const[tid];
        T3_shared[tid] = T3_const[tid];
        sbox_shared[tid] = sbox_const[tid];
    }
    __syncthreads();

    // one thread handle multiple blocks
    int start_block = gid * blocks_per_thread;
    int end_block = start_block + blocks_per_thread > block_num ? block_num : start_block + blocks_per_thread;

    for (int i = start_block; i < end_block; i++)
    {
        decrypt_block(input + i * BLOCK_WORDS, output + i * BLOCK_WORDS, key_shared, T0_shared, T1_shared, T2_shared, T3_shared, sbox_shared);
    }
}

/*
WARP_SHUFFLE
T-table: 4*256*4 bytes, shared memory
key: 44*4 bytes, register file
sbox: 256 bytes, shared memory
*/
__global__ void decrypt_kernel_warp_shuffle(int *input, int *output, int blocks_per_thread, int block_num)
{
    // global id
    int tid = threadIdx.y * blockDim.x + threadIdx.x;
    int gid = blockIdx.x * (blockDim.x * blockDim.y) + tid;

    // register file
    int key_local_0, key_local_1, key_local_2, key_local_3;
    if (tid % 32 <= ROUND_SIZE)
    {
        key_local_0 = key_const[(tid % 32) * 4];
        key_local_1 = key_const[(tid % 32) * 4 + 1];
        key_local_2 = key_const[(tid % 32) * 4 + 2];
        key_local_3 = key_const[(tid % 32) * 4 + 3];
    }

    // shared memory
    __shared__ int T0_shared[256];
    __shared__ int T1_shared[256];
    __shared__ int T2_shared[256];
    __shared__ int T3_shared[256];
    __shared__ uchar sbox_shared[256];

    if (tid < 256)
    {
        T0_shared[tid] = T0_const[tid];
        T1_shared[tid] = T1_const[tid];
        T2_shared[tid] = T2_const[tid];
        T3_shared[tid] = T3_const[tid];
        sbox_shared[tid] = sbox_const[tid];
    }
    __syncthreads();

    // one thread handle multiple blocks
    int start_block = gid * blocks_per_thread;
    int end_block = start_block + blocks_per_thread > block_num ? block_num : start_block + blocks_per_thread;
    int fake_word[4];

    for (int i = start_block; i < start_block + blocks_per_thread; i++)
    {
        decrypt_block_warp_shuffle(i < end_block ? input + i * BLOCK_WORDS : fake_word, i < end_block ? output + i * BLOCK_WORDS : fake_word,
                                   T0_shared, T1_shared, T2_shared, T3_shared, sbox_shared, &key_local_0, &key_local_1, &key_local_2, &key_local_3);
    }
}

#pragma endregion

METRIC AES128_Parallel::decrypt(int threads, OPTIMIZATION opt, uchar input[], uchar output[], int len)
{
    if (len % BLOCK_STATES != 0)
    {
        std::cerr << "[Error] Input size must be multiple of " << BLOCK_STATES << " bytes" << std::endl;
        exit(1);
    }

    int block_num = len / (BLOCK_WORDS * 4);
    int blocks_per_thread = (block_num + threads - 1) / threads;
    printf("Decrypt kernel launcher: %d bytes, %d cipher blocks, %d threads, %d cipher blocks per thread\n", len, block_num, threads, blocks_per_thread);
    dim3 dimBlock(512, 1);
    dim3 dimGrid((threads + 511) / 512, 1, 1);

    // timing
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start);

    // T-table and round key
    cudaMemcpyToSymbol(T0_const, inv_T0, sizeof(inv_T0));
    cudaMemcpyToSymbol(T1_const, inv_T1, sizeof(inv_T1));
    cudaMemcpyToSymbol(T2_const, inv_T2, sizeof(inv_T2));
    cudaMemcpyToSymbol(T3_const, inv_T3, sizeof(inv_T3));

    // round keys
    cudaMemcpyToSymbol(key_const, key_dec, sizeof(key_dec));

    // s-box
    cudaMemcpyToSymbol(sbox_const, inv_sbox, sizeof(inv_sbox));

    // input and output
    int *x_h, *y_h, *x_d, *y_d;
    x_h = reinterpret_cast<int *>(input); // caution: x86 and arm both use little endian
    y_h = reinterpret_cast<int *>(output);
    cudaMalloc((int **)&x_d, len);
    cudaMalloc((int **)&y_d, len);
    cudaMemcpy(x_d, x_h, len, cudaMemcpyHostToDevice);
    // std::cout << (x_h[0] >> 24) << std::endl;
    // std::cout << int(input[3]) << std::endl;

    switch (opt)
    {
    case ALL_CONSTANT:
        decrypt_kernel_all_global<<<dimGrid, dimBlock>>>(x_d, y_d, blocks_per_thread, block_num);
        break;
    case ALL_SHARED:
        decrypt_kernel_all_shared<<<dimGrid, dimBlock>>>(x_d, y_d, blocks_per_thread, block_num);
        break;
    case WARP_SHUFFLE:
        decrypt_kernel_warp_shuffle<<<dimGrid, dimBlock>>>(x_d, y_d, blocks_per_thread, block_num);
        break;
    default:
        std::cerr << "[Error] Invalid optimization option" << std::endl;
        break;
    }

    cudaMemcpy(y_h, y_d, len, cudaMemcpyDeviceToHost);

    // timing
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    float milliseconds = 0;
    cudaEventElapsedTime(&milliseconds, start, stop);
    return METRIC{milliseconds};
}

#pragma endregion