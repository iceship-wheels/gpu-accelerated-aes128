/*
Author: Qiuhong Chen
Date Created: 2024/11/4
*/

#include <iostream>
#include "serial.h"
using namespace std;

int main()
{
    AES128_Serial cipher("0123456789012345");
    char plain_text[17] = "abcdefghijklmnop";
    char cipher_text[17];
    char plain_text_dec[17];
    print_text_hex((uchar *)plain_text, 16);
    cipher.encrypt((uchar *)plain_text, (uchar *)cipher_text, 16);
    print_text_hex((uchar *)cipher_text, 16);
    cipher.decrypt((uchar *)cipher_text, (uchar *)plain_text_dec, 16);
    print_text_hex((uchar *)plain_text_dec, 16);
    return 0;
}