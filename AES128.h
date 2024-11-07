/*
Author: Qiuhong Chen
Date Created: 2024/11/4
*/
#ifndef AES128_H
#define AES128_H

typedef unsigned char uchar;
typedef unsigned int uint32;

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