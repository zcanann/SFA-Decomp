#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80283BF0.h"

extern void fn_8027F0C8(void *p);
extern int fn_80284638(int stream, void *out);
extern int fn_80284038(int dest, int src, u32 size, int flag, undefined4 param_5, undefined4 param_6);
extern void DCStoreRange(void *addr, u32 nBytes);

extern u32 lbl_803CC1E0[];
extern int lbl_803DE344;

/*
 * --INFO--
 *
 * Function: hwRemoveInput
 * EN v1.0 Address: 0x80283BD4
 * EN v1.0 Size: 52b
 */
void hwRemoveInput(u8 idx) {
    fn_8027F0C8(&lbl_803CC1E0[idx * 0x2f]);
}

/*
 * --INFO--
 *
 * Function: hwChangeStudio
 * EN v1.0 Address: 0x80283C08
 * EN v1.0 Size: 164b
 */
int hwChangeStudio(int param_1) {
    u8 mode;
    u32 pos;
    u32 lowBits;
    int entry;

    entry = lbl_803DE344 + param_1 * 0xf4;
    if (*(s8 *)(entry + 0xec) != 2) {
        return 0;
    }
    mode = *(u8 *)(entry + 0x90);
    if (mode == 3) {
        return *(int *)(entry + 0x20) - *(int *)(entry + 0x78);
    }
    if (mode < 3) {
        if (1 < mode) {
            return *(int *)(entry + 0x20) - (*(u32 *)(entry + 0x78) >> 1);
        }
    } else if (5 < mode) {
        return param_1;
    }
    entry = lbl_803DE344 + param_1 * 0xf4;
    pos = *(u32 *)(entry + 0x20);
    lowBits = pos & 0xf;
    entry = ((pos + *(int *)(entry + 0x78) * -2) >> 4) * 0xe;
    if (lowBits < 2) {
        return entry;
    }
    return lowBits + entry - 2;
}

/*
 * --INFO--
 *
 * Function: hwGetPos
 * EN v1.0 Address: 0x80283CAC
 * EN v1.0 Size: 136b
 */
void hwGetPos(int param_1, u32 param_2, int param_3, int param_4, undefined4 param_5,
              undefined4 param_6) {
    u32 size;
    int offset;
    u8 stack[8];

    offset = fn_80284638(param_4, stack);
    size = (param_3 + (param_2 & 0x1f) + 0x1f) & 0xffffffe0;
    param_1 = param_1 + (param_2 & 0xffffffe0);
    DCStoreRange((void *)param_1, size);
    fn_80284038(param_1, offset + (param_2 & 0xffffffe0), size, 1, param_5, param_6);
}

/*
 * --INFO--
 *
 * Function: hwFlushStream
 * EN v1.0 Address: 0x80283D34
 * EN v1.0 Size: 36b
 */
void hwFlushStream(int stream) {
    fn_80284638(stream, 0);
}

/*
 * --INFO--
 *
 * Function: hwInitStream
 * EN v1.0 Address: 0x80283D58
 * EN v1.0 Size: 4b
 */
void hwInitStream(void) {
}
