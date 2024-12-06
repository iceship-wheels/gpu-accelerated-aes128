/*
Author: Qiuhong Chen
Date Created: 2024/11/4
*/

#include <iostream>
#include "AES128.h"
#include "AES_Serial.h"
#include "AES_Parallel.h"
using namespace std;

int read_file(char **ptr, const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        perror("Error opening file");
        return 0;
    }

    // Seek to the end of the file to determine its size
    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    rewind(file); // Return to the beginning of the file

    // Allocate memory for the file content
    char *buffer = (char *)malloc(filesize);
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

void test_parallel()
{
    AES128_Parallel *cipher;

    char plain_text[17] = "abcdefghijklmnop";
    char cipher_text[17];
    char plain_text_dec[17];

    // standard AES128
    cout << endl
         << "=======Parallel AES128=======" << endl;
    cipher = new AES128_Parallel("1234567890123456");
    print_byte_hex((uchar *)plain_text, 16);
    cipher->encrypt(32, 0, (uchar *)plain_text, (uchar *)cipher_text, 16);
    print_byte_hex((uchar *)cipher_text, 16);
    cipher->decrypt(32, 0, (uchar *)cipher_text, (uchar *)plain_text_dec, 16);
    print_byte_hex((uchar *)plain_text_dec, 16);
    delete cipher;
}

void test_large()
{
    AES128_Parallel *cipher;
    cipher = new AES128_Parallel("1234567890123456");

    char filename[] = "input/input_268435456.txt";
    char *plain_text;
    long size = read_file(&plain_text, filename);
    if (size == 0)
    {
        cout << "Error: read file failed" << endl;
        return;
    }
    char *cipher_text = (char *)malloc(size);
    char *plain_text_dec = (char *)malloc(size);
    printf("plain_text: %ld\n", size);

    cipher->encrypt(32, 0, (uchar *)plain_text, (uchar *)cipher_text, size);
    cipher->decrypt(32, 0, (uchar *)cipher_text, (uchar *)plain_text_dec, size);

    // compare plain_text and plain_text_dec
    for (int i = 0; i < sizeof(plain_text); i++)
    {
        if (plain_text[i] != plain_text_dec[i])
        {
            cout << "Error: plain_text and plain_text_dec are not the same" << endl;
            break;
        }
    }

    delete cipher;
}

int main()
{
    verify_tbox();
    // test_serial();
    // test_parallel();
    test_large();

    return 0;
}