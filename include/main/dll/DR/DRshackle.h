#ifndef MAIN_DLL_DR_DRSHACKLE_H_
#define MAIN_DLL_DR_DRSHACKLE_H_

#include "ghidra_import.h"

/* Bitfield: PowerPC big-endian: bit 0 = 0x80, bit 7 = 0x01 */
typedef struct ShackleFlags {
    u8 b7 : 1;  /* 0x80 (sign bit) */
    u8 b6 : 1;  /* 0x40 */
    u8 b5 : 1;  /* 0x20 */
    u8 b4 : 1;  /* 0x10 */
    u8 b3 : 1;  /* 0x08 */
    u8 b2 : 1;  /* 0x04 */
    u8 b1 : 1;  /* 0x02 */
    u8 b0 : 1;  /* 0x01 */
} ShackleFlags;

int fn_801EA854(int obj, int state);
int fn_801EAAC0(int obj, int state);

#endif /* MAIN_DLL_DR_DRSHACKLE_H_ */
