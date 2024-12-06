/*
Author: Qiuhong Chen
Date Created: 2024/11/4
*/
#ifndef __AES128_H__
#define __AES128_H__

typedef unsigned char uchar;
typedef unsigned int uint32;

void print_byte_hex(uchar text[], int len);
void print_word_hex(uint32 text[], int len);

uchar gfmul(uchar a, uchar b);

void verify_tbox();

extern uchar sbox[256];
extern uchar inv_sbox[256];
extern uint32 T0[256];
extern uint32 T1[256];
extern uint32 T2[256];
extern uint32 T3[256];
extern uint32 inv_T0[256];
extern uint32 inv_T1[256];
extern uint32 inv_T2[256];
extern uint32 inv_T3[256];

#endif