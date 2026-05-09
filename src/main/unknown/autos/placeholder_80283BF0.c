#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80283BF0.h"

extern void salRemoveStudioInput(void *p);
extern int aramGetStreamBufferAddress(int stream, void *out);
extern void aramUploadData(int dest, int src, u32 size, int mode, undefined4 callback,
                           undefined4 callbackArg);
extern void DCStoreRange(void *addr, u32 nBytes);

extern u8 lbl_803CC1E0[];
extern int dspVoice;

/*
 * --INFO--
 *
 * Function: hwRemoveInput
 * EN v1.0 Address: 0x80283BD4
 * EN v1.0 Size: 52b
 */
void hwRemoveInput(u32 idx) {
    u32 offset = (idx & 0xff) * 0xbc;
    salRemoveStudioInput(lbl_803CC1E0 + offset);
}

/*
 * --INFO--
 *
 * Function: hwChangeStudio
 * EN v1.0 Address: 0x80283C08
 * EN v1.0 Size: 164b
 */
int hwChangeStudio(int param_1) {
    int mode;
    u32 pos;
    u32 lowBits;
    int entry;
    int base;
    int offset;

    offset = param_1 * 0xf4;
    base = dspVoice;
    entry = base + offset;
    if (*(u8 *)(entry + 0xec) != 2) {
        return 0;
    }
    mode = *(u8 *)(entry + 0x90);
    switch (mode) {
    case 0:
    case 1:
    case 4:
    case 5:
        entry = base + offset;
        pos = *(u32 *)(entry + 0x20);
        entry = ((pos - 2 * *(int *)(entry + 0x78)) >> 4) * 0xe;
        lowBits = pos & 0xf;
        if (lowBits < 2) {
            return entry;
        }
        entry += lowBits;
        return entry - 2;
    case 3:
        return *(int *)(entry + 0x20) - *(int *)(entry + 0x78);
    case 2:
        return *(int *)(entry + 0x20) - (*(u32 *)(entry + 0x78) >> 1);
    default:
        return param_1;
    }
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

    offset = aramGetStreamBufferAddress(param_4, stack);
    param_3 += param_2 & 0x1f;
    param_2 &= 0xffffffe0;
    size = (param_3 + 0x1f) & 0xffffffe0;
    param_1 = param_1 + param_2;
    DCStoreRange((void *)param_1, size);
    aramUploadData(param_1, offset + param_2, size, 1, param_5, param_6);
}

/*
 * --INFO--
 *
 * Function: hwFlushStream
 * EN v1.0 Address: 0x80283D34
 * EN v1.0 Size: 36b
 */
void hwFlushStream(int stream) {
    aramGetStreamBufferAddress(stream, 0);
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
