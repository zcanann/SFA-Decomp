#ifndef MAIN_DLL_DR_DRPICKUP_H_
#define MAIN_DLL_DR_DRPICKUP_H_

#include "ghidra_import.h"

/* Bitfield: PowerPC big-endian: bit 0 = 0x80, bit 7 = 0x01 */
typedef struct PickupFlags {
    u8 b7 : 1;  /* 0x80 (sign bit) */
    u8 b6 : 1;  /* 0x40 */
    u8 b5 : 1;  /* 0x20 */
    u8 b4 : 1;  /* 0x10 */
    u8 b3 : 1;  /* 0x08 */
    u8 b2 : 1;  /* 0x04 */
    u8 b1 : 1;  /* 0x02 */
    u8 b0 : 1;  /* 0x01 */
} PickupFlags;

void FUN_801ec1ac(int param_1,int param_2);

#endif /* MAIN_DLL_DR_DRPICKUP_H_ */
