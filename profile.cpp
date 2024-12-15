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

void profile_gpu(OPTIMIZATION opt)
{
    AES128_Parallel *cipher;
    cipher = new AES128_Parallel("1234567890123456");

    uchar *plain_text, *cipher_text, *plain_text_dec;
    std::string filename = "input/input_268435456.txt";
    size_t size = read_file_malloc(&plain_text, filename.c_str());
    if (size == 0)
    {
        cout << "Error: read file failed" << endl;
        return;
    }
    cipher_text = (uchar *)malloc(size);
    plain_text_dec = (uchar *)malloc(size);

    cipher->encrypt(1024, opt, plain_text, cipher_text, size);

    free(plain_text);
    free(cipher_text);
    free(plain_text_dec);
    delete cipher;
}

int main(int argc, char *argv[])
{
    // profile_gpu(OPTIMIZATION::ALL_CONSTANT);
    // profile_gpu(OPTIMIZATION::ALL_SHARED);
    profile_gpu(OPTIMIZATION::WARP_SHUFFLE);
    return 0;
}