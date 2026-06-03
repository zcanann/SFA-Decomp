#ifndef MAIN_DLL_DR_DRSHACKLE_H_
#define MAIN_DLL_DR_DRSHACKLE_H_

#include "ghidra_import.h"

/* Bitfield: PowerPC big-endian: bit 0 = 0x80, bit 7 = 0x01 */
typedef struct ShackleFlags {
    u8 unused7 : 1;       /* 0x80 (sign bit) */
    u8 unused6 : 1;       /* 0x40 */
    u8 unused5 : 1;       /* 0x20 */
    u8 unused4 : 1;       /* 0x10 */
    u8 active : 1;        /* 0x08 */
    u8 unused2 : 1;       /* 0x04 */
    u8 unused1 : 1;       /* 0x02 */
    u8 positionAnchored : 1; /* 0x01 */
} ShackleFlags;

int drshackle_updateSwingBlend(int obj, int state);
int drshackle_updateAttachedPosition(int obj, int state);

#endif /* MAIN_DLL_DR_DRSHACKLE_H_ */
