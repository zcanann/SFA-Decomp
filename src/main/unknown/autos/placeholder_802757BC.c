#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_802757BC.h"

extern u32 sndRand(void);
extern u32 hwIsActive(u8 voiceId);

typedef struct VoiceParams {
    u32 flags;
    u32 range;
} VoiceParams;

typedef struct VoiceState {
    u8 unk0[0x34];
    void *playPtr;
    u8 unk38[0xa6];
    u16 counter;
    u8 unkAC[0x44];
    u8 voiceId;
    u8 unkF1[0x1f];
    void *baseTable;
    u8 unk114[0x114 - 0x10C - 4];
    u32 inputFlags;
    u32 outputFlags;
} VoiceState;

/*
 * --INFO--
 *
 * Function: fn_8027566C
 * EN v1.0 Address: 0x8027566C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802757BC
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8027566C(int state, int params)
{
    u32 flags;

    if (*(u16 *)(state + 0xaa) == 0) {
        if ((*(u32 *)(params + 0) >> 16) & 1) {
            *(u16 *)(state + 0xaa) = (u16)sndRand() % (u16)(*(u32 *)(params + 4) >> 16);
        } else {
            *(u16 *)(state + 0xaa) = (u16)(*(u32 *)(params + 4) >> 16);
        }
        if (*(u16 *)(state + 0xaa) == 0xffff) {
            goto check_flags;
        }
        *(u16 *)(state + 0xaa) = *(u16 *)(state + 0xaa) + 1;
    } else {
        if (*(u16 *)(state + 0xaa) == 0xffff) {
            goto check_flags;
        }
    }
    *(u16 *)(state + 0xaa) = *(u16 *)(state + 0xaa) - 1;
    if (*(u16 *)(state + 0xaa) == 0) {
        return;
    }

check_flags:
    flags = *(u32 *)(params + 0);
    if ((flags >> 8) & 1) {
        if ((*(u32 *)(state + 0x114) & 0x100) == 0 && (*(u32 *)(state + 0x118) & 0x8) != 0) {
            *(u16 *)(state + 0xaa) = 0;
            return;
        }
    }
    if ((flags >> 24) & 1) {
        if ((*(u32 *)(state + 0x114) & 0) == 0 && (*(u32 *)(state + 0x118) & 0x20) == 0) {
            if (hwIsActive(*(u8 *)(state + 0xf4)) == 0) {
                *(u16 *)(state + 0xaa) = 0;
                return;
            }
        }
    }
    *(int *)(state + 0x38) = *(int *)(state + 0x34) + ((*(u32 *)(params + 4) & 0xffff) << 3);
}
