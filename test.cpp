/*
Author: Qiuhong Chen
Date Created: 2024/11/4
*/

#include <iostream>
#include <vector>
#include "AES128.h"
#include "AES_Serial.h"
#include "AES_Parallel.h"
using namespace std;

size_t read_file_malloc(uchar **ptr, const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        perror("Error opening file");
        return 0;
    }

    // Seek to the end of the file to determine its size
    fseek(file, 0, SEEK_END);
    size_t filesize = ftell(file);
    rewind(file); // Return to the beginning of the file

    // Allocate memory for the file content
    uchar *buffer = (uchar *)malloc(filesize);
    if (buffer == NULL)
    {
        perror("Error allocating memory");
        fclose(file);
        return 0;
    }

    // Read the entire file into the buffer
    size_t read_size = fread(buffer, 1, filesize, file);
    if (read_size != filesize)
    {
        perror("Error reading file");
        free(buffer);
        fclose(file);
        return 0;
    }

    fclose(file);
    *ptr = buffer;
    return filesize;
}

bool compare_bytes(const uchar *a, const uchar *b, int len)
{
    for (int i = 0; i < len; i++)
    {
        if (a[i] != b[i])
        {
            printf("Error at position %d: %x != %x\n", i, a[i], b[i]);
            return false;
        }
    }
    return true;
}

void test_serial()
{
    AES128_Serial *cipher;

    char plain_text[17] = "abcdefghijklmnop";
    char cipher_text[17];
    char plain_text_dec[17];

    // standard AES128
    cout << endl
         << "=======Serial AES128 (Standard)=======" << endl;
    cipher = new AES128_Serial_Std("1234567890123456");
    print_byte_hex((uchar *)plain_text, 16);
    cipher->encrypt((uchar *)plain_text, (uchar *)cipher_text, 16);
    print_byte_hex((uchar *)cipher_text, 16);
    cipher->decrypt((uchar *)cipher_text, (uchar *)plain_text_dec, 16);
    print_byte_hex((uchar *)plain_text_dec, 16);
    delete cipher;

    // fast AES128
    cout << endl
         << "=======Serial AES128 (Fast)=======" << endl;
    cipher = new AES128_Serial_Fast("1234567890123456");
    print_byte_hex((uchar *)plain_text, 16);
    cipher->encrypt((uchar *)plain_text, (uchar *)cipher_text, 16);
    print_byte_hex((uchar *)cipher_text, 16);
    cipher->decrypt((uchar *)cipher_text, (uchar *)plain_text_dec, 16);
    print_byte_hex((uchar *)plain_text_dec, 16);
    delete cipher;
}

void test_parallel_1()
{
    AES128_Parallel *cipher;

    char plain_text[17] = "abcdefghijklmnop";
    char cipher_text[17];
    char plain_text_dec[17];

    // standard AES128
    cout << endl
         << "=======Parallel AES128 (All Global)=======" << endl;
    cipher = new AES128_Parallel("1234567890123456");
    print_byte_hex((uchar *)plain_text, 16);
    cipher->encrypt(32, OPTIMIZATION::ALL_CONSTANT, (uchar *)plain_text, (uchar *)cipher_text, 16);
    print_byte_hex((uchar *)cipher_text, 16);
    cipher->decrypt(32, OPTIMIZATION::ALL_CONSTANT, (uchar *)cipher_text, (uchar *)plain_text_dec, 16);
    print_byte_hex((uchar *)plain_text_dec, 16);
    delete cipher;
}

void test_parallel_2()
{
    AES128_Parallel *cipher;

    char plain_text[17] = "abcdefghijklmnop";
    char cipher_text[17];
    char plain_text_dec[17];

    // standard AES128
    cout << endl
         << "=======Parallel AES128 (All Shared)=======" << endl;
    cipher = new AES128_Parallel("1234567890123456");
    print_byte_hex((uchar *)plain_text, 16);
    cipher->encrypt(32, OPTIMIZATION::ALL_SHARED, (uchar *)plain_text, (uchar *)cipher_text, 16);
    print_byte_hex((uchar *)cipher_text, 16);
    cipher->decrypt(32, OPTIMIZATION::ALL_SHARED, (uchar *)cipher_text, (uchar *)plain_text_dec, 16);
    print_byte_hex((uchar *)plain_text_dec, 16);
    delete cipher;
}

void test_parallel_3()
{
    AES128_Parallel *cipher;

    char plain_text[17] = "abcdefghijklmnop";
    char cipher_text[17];
    char plain_text_dec[17];

    // standard AES128
    cout << endl
         << "=======Parallel AES128 (Warp Shuffle)=======" << endl;
    cipher = new AES128_Parallel("1234567890123456");
    print_byte_hex((uchar *)plain_text, 16);
    cipher->encrypt(32, OPTIMIZATION::WARP_SHUFFLE, (uchar *)plain_text, (uchar *)cipher_text, 16);
    print_byte_hex((uchar *)cipher_text, 16);
    cipher->decrypt(32, OPTIMIZATION::WARP_SHUFFLE, (uchar *)cipher_text, (uchar *)plain_text_dec, 16);
    print_byte_hex((uchar *)plain_text_dec, 16);
    delete cipher;
}

void test_large()
{
    int iterations = 1;

    // ciphers
    AES128_Serial_Std *serial_std_cipher;
    serial_std_cipher = new AES128_Serial_Std("1234567890123456");
    AES128_Serial_Fast *serial_fast_cipher;
    serial_fast_cipher = new AES128_Serial_Fast("1234567890123456");
    AES128_Parallel *parallel_cipher;
    parallel_cipher = new AES128_Parallel("1234567890123456");

    // input files
    std::vector<std::string> filenames;
    for (int i = 10; i < 31; i += 2)
    {
        filenames.push_back("input/input_" + std::to_string(1 << i) + ".txt");
    }
    uchar *plain_text, *cipher_text, *plain_text_dec;

    METRIC enc, dec;
    vector<float> cpu_std_enc, cpu_std_dec, cpu_fast_enc, cpu_fast_dec;
    vector<float> gpu_all_constant_enc, gpu_all_constant_dec, gpu_all_shared_enc, gpu_all_shared_dec, gpu_warp_shuffle_enc, gpu_warp_shuffle_dec;
    for (int i = 0; i < filenames.size(); i++)
    {
        printf("\n=======File %s=======\n", filenames[i].c_str());

        // time of each iteration
        vector<float> cpu_std_enc_iter, cpu_std_dec_iter, cpu_fast_enc_iter, cpu_fast_dec_iter;
        vector<float> gpu_all_constant_enc_iter, gpu_all_constant_dec_iter, gpu_all_shared_enc_iter, gpu_all_shared_dec_iter, gpu_warp_shuffle_enc_iter, gpu_warp_shuffle_dec_iter;

        // memory allocation
        size_t size = read_file_malloc(&plain_text, filenames[i].c_str());
        if (size == 0)
        {
            cout << "Error: read file failed" << endl;
            break;
        }
        cipher_text = (uchar *)malloc(size);
        plain_text_dec = (uchar *)malloc(size);

        for (int j = 0; j < iterations; j++)
        {
            std::cout << "Iteration " << j << std::endl;

            if (size <= (1 << 23))
            {
                enc = serial_std_cipher->encrypt(plain_text, cipher_text, size);
                dec = serial_std_cipher->decrypt(cipher_text, plain_text_dec, size);
                if (!compare_bytes(plain_text, plain_text_dec, size))
                {
                    cout << "Serial (Standard): Failed" << endl;
                    break;
                }
                cpu_std_dec_iter.push_back(dec.milliseconds);
                cpu_std_enc_iter.push_back(enc.milliseconds);
            }

            if (size <= (1 << 29))
            {
                enc = serial_fast_cipher->encrypt(plain_text, cipher_text, size);
                dec = serial_fast_cipher->decrypt(cipher_text, plain_text_dec, size);
                if (!compare_bytes(plain_text, plain_text_dec, size))
                {
                    cout << "Serial (Fast): Failed" << endl;
                    break;
                }
                cpu_fast_dec_iter.push_back(dec.milliseconds);
                cpu_fast_enc_iter.push_back(enc.milliseconds);
            }

            enc = parallel_cipher->encrypt(1024, OPTIMIZATION::ALL_CONSTANT, plain_text, cipher_text, size);
            dec = parallel_cipher->decrypt(1024, OPTIMIZATION::ALL_CONSTANT, cipher_text, plain_text_dec, size);
            if (!compare_bytes(plain_text, plain_text_dec, size))
            {
                cout << "Parallel (ALL CONSTANT): Failed" << endl;
                break;
            }
            gpu_all_constant_enc_iter.push_back(enc.milliseconds);
            gpu_all_constant_dec_iter.push_back(dec.milliseconds);

            enc = parallel_cipher->encrypt(1024, OPTIMIZATION::ALL_SHARED, plain_text, cipher_text, size);
            dec = parallel_cipher->decrypt(1024, OPTIMIZATION::ALL_SHARED, cipher_text, plain_text_dec, size);
            if (!compare_bytes(plain_text, plain_text_dec, size))
            {
                cout << "Parallel (ALL SHARED): Failed" << endl;
                break;
            }
            gpu_all_shared_enc_iter.push_back(enc.milliseconds);
            gpu_all_shared_dec_iter.push_back(dec.milliseconds);

            enc = parallel_cipher->encrypt(1024, OPTIMIZATION::WARP_SHUFFLE, plain_text, cipher_text, size);
            dec = parallel_cipher->decrypt(1024, OPTIMIZATION::WARP_SHUFFLE, cipher_text, plain_text_dec, size);
            if (!compare_bytes(plain_text, plain_text_dec, size))
            {
                cout << "Parallel (WARP SHUFFLE): Failed" << endl;
                break;
            }
            gpu_warp_shuffle_enc_iter.push_back(enc.milliseconds);
            gpu_warp_shuffle_dec_iter.push_back(dec.milliseconds);
        }

        // free memory
        free(plain_text);
        free(cipher_text);
        free(plain_text_dec);

        // calculate average
        if (cpu_std_enc_iter.size() > 0)
        {
            float sum = 0;
            for (int j = 0; j < cpu_std_enc_iter.size(); j++)
            {
                sum += cpu_std_enc_iter[j];
            }
            cpu_std_enc.push_back(sum / cpu_std_enc_iter.size());
        }

        if (cpu_std_dec_iter.size() > 0)
        {
            float sum = 0;
            for (int j = 0; j < cpu_std_dec_iter.size(); j++)
            {
                sum += cpu_std_dec_iter[j];
            }
            cpu_std_dec.push_back(sum / cpu_std_dec_iter.size());
        }

        if (cpu_fast_enc_iter.size() > 0)
        {
            float sum = 0;
            for (int j = 0; j < cpu_fast_enc_iter.size(); j++)
            {
                sum += cpu_fast_enc_iter[j];
            }
            cpu_fast_enc.push_back(sum / cpu_fast_enc_iter.size());
        }

        if (cpu_fast_dec_iter.size() > 0)
        {
            float sum = 0;
            for (int j = 0; j < cpu_fast_dec_iter.size(); j++)
            {
                sum += cpu_fast_dec_iter[j];
            }
            cpu_fast_dec.push_back(sum / cpu_fast_dec_iter.size());
        }

        if (gpu_all_constant_enc_iter.size() > 0)
        {
            float sum = 0;
            for (int j = 0; j < gpu_all_constant_enc_iter.size(); j++)
            {
                sum += gpu_all_constant_enc_iter[j];
            }
            gpu_all_constant_enc.push_back(sum / gpu_all_constant_enc_iter.size());
        }

        if (gpu_all_constant_dec_iter.size() > 0)
        {
            float sum = 0;
            for (int j = 0; j < gpu_all_constant_dec_iter.size(); j++)
            {
                sum += gpu_all_constant_dec_iter[j];
            }
            gpu_all_constant_dec.push_back(sum / gpu_all_constant_dec_iter.size());
        }

        if (gpu_all_shared_enc_iter.size() > 0)
        {
            float sum = 0;
            for (int j = 0; j < gpu_all_shared_enc_iter.size(); j++)
            {
                sum += gpu_all_shared_enc_iter[j];
            }
            gpu_all_shared_enc.push_back(sum / gpu_all_shared_enc_iter.size());
        }

        if (gpu_all_shared_dec_iter.size() > 0)
        {
            float sum = 0;
            for (int j = 0; j < gpu_all_shared_dec_iter.size(); j++)
            {
                sum += gpu_all_shared_dec_iter[j];
            }
            gpu_all_shared_dec.push_back(sum / gpu_all_shared_dec_iter.size());
        }

        if (gpu_warp_shuffle_enc_iter.size() > 0)
        {
            float sum = 0;
            for (int j = 0; j < gpu_warp_shuffle_enc_iter.size(); j++)
            {
                sum += gpu_warp_shuffle_enc_iter[j];
            }
            gpu_warp_shuffle_enc.push_back(sum / gpu_warp_shuffle_enc_iter.size());
        }

        if (gpu_warp_shuffle_dec_iter.size() > 0)
        {
            float sum = 0;
            for (int j = 0; j < gpu_warp_shuffle_dec_iter.size(); j++)
            {
                sum += gpu_warp_shuffle_dec_iter[j];
            }
            gpu_warp_shuffle_dec.push_back(sum / gpu_warp_shuffle_dec_iter.size());
        }
    }

    // write results to JSON
    FILE *fp = fopen("output/result.json", "w");
    if (fp == NULL)
    {
        perror("Error opening file");
        return;
    }
    fprintf(fp, "{\n");

    fprintf(fp, "\"file_sizes\": [");
    for (int i = 10; i < 31; i += 2)
    {
        fprintf(fp, "%d", 1 << i);
        if (i != 30)
            fprintf(fp, ", ");
    }
    fprintf(fp, "],\n");

    fprintf(fp, "\"cpu_std_enc\": [");
    for (int i = 0; i < cpu_std_enc.size(); i++)
    {
        fprintf(fp, "%f", cpu_std_enc[i]);
        if (i != cpu_std_enc.size() - 1)
            fprintf(fp, ", ");
    }
    fprintf(fp, "],\n");

    fprintf(fp, "\"cpu_std_dec\": [");
    for (int i = 0; i < cpu_std_dec.size(); i++)
    {
        fprintf(fp, "%f", cpu_std_dec[i]);
        if (i != cpu_std_dec.size() - 1)
            fprintf(fp, ", ");
    }
    fprintf(fp, "],\n");

    fprintf(fp, "\"cpu_fast_enc\": [");
    for (int i = 0; i < cpu_fast_enc.size(); i++)
    {
        fprintf(fp, "%f", cpu_fast_enc[i]);
        if (i != cpu_fast_enc.size() - 1)
            fprintf(fp, ", ");
    }
    fprintf(fp, "],\n");

    fprintf(fp, "\"cpu_fast_dec\": [");
    for (int i = 0; i < cpu_fast_dec.size(); i++)
    {
        fprintf(fp, "%f", cpu_fast_dec[i]);
        if (i != cpu_fast_dec.size() - 1)
            fprintf(fp, ", ");
    }
    fprintf(fp, "],\n");

    fprintf(fp, "\"gpu_all_constant_enc\": [");
    for (int i = 0; i < gpu_all_constant_enc.size(); i++)
    {
        fprintf(fp, "%f", gpu_all_constant_enc[i]);
        if (i != gpu_all_constant_enc.size() - 1)
            fprintf(fp, ", ");
    }
    fprintf(fp, "],\n");

    fprintf(fp, "\"gpu_all_constant_dec\": [");
    for (int i = 0; i < gpu_all_constant_dec.size(); i++)
    {
        fprintf(fp, "%f", gpu_all_constant_dec[i]);
        if (i != gpu_all_constant_dec.size() - 1)
            fprintf(fp, ", ");
    }
    fprintf(fp, "],\n");

    fprintf(fp, "\"gpu_all_shared_enc\": [");
    for (int i = 0; i < gpu_all_shared_enc.size(); i++)
    {
        fprintf(fp, "%f", gpu_all_shared_enc[i]);
        if (i != gpu_all_shared_enc.size() - 1)
            fprintf(fp, ", ");
    }
    fprintf(fp, "],\n");

    fprintf(fp, "\"gpu_all_shared_dec\": [");
    for (int i = 0; i < gpu_all_shared_dec.size(); i++)
    {
        fprintf(fp, "%f", gpu_all_shared_dec[i]);
        if (i != gpu_all_shared_dec.size() - 1)
            fprintf(fp, ", ");
    }
    fprintf(fp, "],\n");

    fprintf(fp, "\"gpu_warp_shuffle_enc\": [");
    for (int i = 0; i < gpu_warp_shuffle_enc.size(); i++)
    {
        fprintf(fp, "%f", gpu_warp_shuffle_enc[i]);
        if (i != gpu_warp_shuffle_enc.size() - 1)
            fprintf(fp, ", ");
    }
    fprintf(fp, "],\n");

    fprintf(fp, "\"gpu_warp_shuffle_dec\": [");
    for (int i = 0; i < gpu_warp_shuffle_dec.size(); i++)
    {
        fprintf(fp, "%f", gpu_warp_shuffle_dec[i]);
        if (i != gpu_warp_shuffle_dec.size() - 1)
            fprintf(fp, ", ");
    }
    fprintf(fp, "]\n");

    fprintf(fp, "}\n");
    fclose(fp);

    delete serial_std_cipher;
    delete serial_fast_cipher;
    delete parallel_cipher;
}

int main()
{
    // verify_tbox();
    // test_serial();
    // test_parallel_1();
    // test_parallel_2();
    // test_parallel_3();
    test_large();

    return 0;
}