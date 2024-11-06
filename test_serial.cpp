/*
Author: Qiuhong Chen
Date Created: 2024/11/4
*/

#include <iostream>
#include "AES_Serial.h"
#include "AES128.h"
using namespace std;

int main()
{
    AES128_serial *cipher;

    // verify_tbox();

    // standard AES128
    cipher = new AES128_serial_standard("1234567890123456");
    char plain_text[17] = "abcdefghijklmnop";
    char cipher_text[17];
    char plain_text_dec[17];
    print_text_hex((uchar *)plain_text, 16);
    cipher->encrypt((uchar *)plain_text, (uchar *)cipher_text, 16);
    print_text_hex((uchar *)cipher_text, 16);
    cipher->decrypt((uchar *)cipher_text, (uchar *)plain_text_dec, 16);
    print_text_hex((uchar *)plain_text_dec, 16);
    delete cipher;
    // fast AES128

    return 0;
}