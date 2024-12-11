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

size_t read_file(uchar **ptr, const char *filename)
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

bool compare_bytes(uchar *a, uchar *b, int len)
{
    for (int i = 0; i < len; i++)
    {
        if (a[i] != b[i])
        {
            printf("Error: a[%d] = %d, b[%d] = %d\n", i, a[i], i, b[i]);
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
    cipher->encrypt(32, OPTIMIZATION::ALL_GLOBAL, (uchar *)plain_text, (uchar *)cipher_text, 16);
    print_byte_hex((uchar *)cipher_text, 16);
    // cipher->decrypt(32, 0, (uchar *)cipher_text, (uchar *)plain_text_dec, 16);
    // print_byte_hex((uchar *)plain_text_dec, 16);
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
    cipher->decrypt(32, 0, (uchar *)cipher_text, (uchar *)plain_text_dec, 16);
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
    // cipher->decrypt(32, 0, (uchar *)cipher_text, (uchar *)plain_text_dec, 16);
    // print_byte_hex((uchar *)plain_text_dec, 16);
    delete cipher;
}

void test_large()
{
    // ciphers
    AES128_Serial_Std *serial_std_cipher;
    serial_std_cipher = new AES128_Serial_Std("1234567890123456");
    AES128_Serial_Fast *serial_fast_cipher;
    serial_fast_cipher = new AES128_Serial_Fast("1234567890123456");
    AES128_Parallel *parallel_cipher;
    parallel_cipher = new AES128_Parallel("1234567890123456");

    // input files
    std::vector<std::string> filenames = {"input/input_8192.txt", "input/input_65536.txt", "input/input_524288.txt", "input/input_4194304.txt", "input/input_33554432.txt", "input/input_268435456.txt"};
    uchar *plain_text, *cipher_text, *plain_text_dec;

    for (int i = 0; i < filenames.size(); i++)
    {
        printf("=======File %s=======\n", filenames[i].c_str());
        size_t size = read_file(&plain_text, filenames[i].c_str());
        if (size == 0)
        {
            cout << "Error: read file failed" << endl;
            break;
        }
        cipher_text = (uchar *)malloc(size);
        plain_text_dec = (uchar *)malloc(size);

        if (size <= (1 << 20))
        {
            serial_std_cipher->encrypt(plain_text, cipher_text, size);
            serial_std_cipher->decrypt(cipher_text, plain_text_dec, size);
            std::cout << "Serial Std: " << (compare_bytes(plain_text, plain_text_dec, size) ? "Success" : "Failed") << std::endl;

            serial_fast_cipher->encrypt(plain_text, cipher_text, size);
            serial_fast_cipher->decrypt(cipher_text, plain_text_dec, size);
            std::cout << "Serial Fast: " << (compare_bytes(plain_text, plain_text_dec, size) ? "Success" : "Failed") << std::endl;
        }

        parallel_cipher->encrypt(1024, OPTIMIZATION::ALL_GLOBAL, plain_text, cipher_text, size);
        parallel_cipher->decrypt(1024, 0, cipher_text, plain_text_dec, size);
        std::cout << "Parallel ALL GLOBAL: " << (compare_bytes(plain_text, plain_text_dec, size) ? "Success" : "Failed") << std::endl;

        parallel_cipher->encrypt(1024, OPTIMIZATION::ALL_SHARED, plain_text, cipher_text, size);
        parallel_cipher->decrypt(1024, 0, cipher_text, plain_text_dec, size);
        std::cout << "Parallel ALL SHARED: " << (compare_bytes(plain_text, plain_text_dec, size) ? "Success" : "Failed") << std::endl;

        parallel_cipher->encrypt(1024, OPTIMIZATION::WARP_SHUFFLE, plain_text, cipher_text, size);
        parallel_cipher->decrypt(1024, 0, cipher_text, plain_text_dec, size);
        std::cout << "Parallel WARP SHUFFLE: " << (compare_bytes(plain_text, plain_text_dec, size) ? "Success" : "Failed") << std::endl;

        free(plain_text);
        free(cipher_text);
        free(plain_text_dec);
    }
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