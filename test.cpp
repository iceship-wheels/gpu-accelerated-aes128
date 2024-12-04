/*
Author: Qiuhong Chen
Date Created: 2024/11/4
*/

#include <iostream>
#include "AES_Serial.h"
#include "AES_Parallel.h"
#include "AES128.h"
using namespace std;

void test_serial()
{
    AES128_Serial *cipher;

    char plain_text[17] = "abcdefghijklmnop";
    char cipher_text[17];
    char plain_text_dec[17];

    // standard AES128
    cout << endl
         << "=======standard AES128=======" << endl;
    cipher = new AES128_Serial_Std("1234567890123456");
    print_byte_hex((uchar *)plain_text, 16);
    cipher->encrypt((uchar *)plain_text, (uchar *)cipher_text, 16);
    print_byte_hex((uchar *)cipher_text, 16);
    cipher->decrypt((uchar *)cipher_text, (uchar *)plain_text_dec, 16);
    print_byte_hex((uchar *)plain_text_dec, 16);
    delete cipher;

    // fast AES128
    cout << endl
         << "=======fast AES128=======" << endl;
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
    cipher = new AES128_Parallel();
    print_byte_hex((uchar *)plain_text, 16);
    cipher->encrypt(32, 0, (uchar *)plain_text, (uchar *)cipher_text, 16);
    print_byte_hex((uchar *)cipher_text, 16);
    delete cipher;
}

int main()
{
    verify_tbox();
    // test_serial();
    test_parallel();

    return 0;
}