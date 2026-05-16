#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80283BF0.h"

extern void salRemoveStudioInput(void *p);
extern int aramGetStreamBufferAddress(int stream, void *out);
extern void aramUploadData(int dest, int src, u32 size, int mode, undefined4 callback,
                           undefined4 callbackArg);
extern void DCStoreRange(void *addr, u32 nBytes);

extern u8 lbl_803CC1E0[];
extern u8 *dspVoice;

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
int hwChangeStudio(int slot) {
    int mode;
    u32 pos;
    u32 lowBits;
    int samplePos;
    u8 *voice;
    u8 *base;
    int offset;

    offset = slot * 0xf4;
    base = dspVoice;
    voice = base + offset;
    if (*(u8 *)(voice + 0xec) != 2) {
        return 0;
    }
    mode = *(u8 *)(voice + 0x90);
    switch (mode) {
    case 0:
    case 1:
    case 4:
    case 5:
        voice = base + offset;
        pos = *(u32 *)(voice + 0x20);
        samplePos = ((pos - 2 * *(int *)(voice + 0x78)) >> 4) * 0xe;
        lowBits = pos & 0xf;
        if (lowBits < 2) {
            return samplePos;
        }
        samplePos += lowBits;
        return samplePos - 2;
    case 3:
        return *(int *)(voice + 0x20) - *(int *)(voice + 0x78);
    case 2:
        return *(int *)(voice + 0x20) - (*(u32 *)(voice + 0x78) >> 1);
    default:
        return slot;
    }
}

/*
 * --INFO--
 *
 * Function: hwGetPos
 * EN v1.0 Address: 0x80283CAC
 * EN v1.0 Size: 136b
 */
void hwGetPos(int dest, u32 streamPos, int byteCount, int stream, undefined4 callback,
              undefined4 callbackArg) {
    int alignedDest;
    u32 alignedStreamPos;
    int alignedByteCount;
    u32 size;
    int offset;
    u8 stack[8];

    alignedDest = dest;
    alignedStreamPos = streamPos;
    alignedByteCount = byteCount;
    offset = aramGetStreamBufferAddress(stream, stack);
    alignedByteCount += alignedStreamPos & 0x1f;
    alignedStreamPos &= 0xffffffe0;
    size = (alignedByteCount + 0x1f) & 0xffffffe0;
    alignedDest += alignedStreamPos;
    DCStoreRange((void *)alignedDest, size);
    aramUploadData(alignedDest, offset + alignedStreamPos, size, 1, callback, callbackArg);
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
