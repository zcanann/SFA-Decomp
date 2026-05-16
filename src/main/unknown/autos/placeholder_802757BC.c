#include "ghidra_import.h"
#include "main/audio/mcmd.h"
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
 * Function: mcmdLoop
 * EN v1.0 Address: 0x8027566C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802757BC
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void mcmdLoop(int state, int params)
{
    u16 counter;
    u32 zero;
    u32 flags;

    if (*(u16 *)(state + MCMD_VOICE_LOOP_COUNTER_OFFSET) == 0) {
        if (*(u32 *)(params + 0) & MCMD_LOOP_RANDOM_DELAY_FLAG) {
            *(u16 *)(state + MCMD_VOICE_LOOP_COUNTER_OFFSET) =
                (u16)sndRand() % (u16)(*(u32 *)(params + 4) >> 16);
        } else {
            *(u16 *)(state + MCMD_VOICE_LOOP_COUNTER_OFFSET) =
                (u16)(*(u32 *)(params + 4) >> 16);
        }
        if (*(u16 *)(state + MCMD_VOICE_LOOP_COUNTER_OFFSET) == MCMD_LOOP_COUNTER_FOREVER) {
            goto check_flags;
        }
        *(u16 *)(state + MCMD_VOICE_LOOP_COUNTER_OFFSET) =
            *(u16 *)(state + MCMD_VOICE_LOOP_COUNTER_OFFSET) + 1;
    } else {
        if (*(u16 *)(state + MCMD_VOICE_LOOP_COUNTER_OFFSET) == MCMD_LOOP_COUNTER_FOREVER) {
            goto check_flags;
        }
    }
    counter = *(u16 *)(state + MCMD_VOICE_LOOP_COUNTER_OFFSET) - 1;
    *(u16 *)(state + MCMD_VOICE_LOOP_COUNTER_OFFSET) = counter;
    if (counter == 0) {
        return;
    }

check_flags:
    flags = *(u32 *)(params + 0);
    if (flags & MCMD_LOOP_WAIT_FOR_KEYOFF_FLAG) {
        if (((*(u32 *)(state + MCMD_VOICE_INPUT_FLAGS_OFFSET) & MCMD_VOICE_KEYOFF_INPUT_FLAG) ==
             0) &&
            ((*(u32 *)(state + MCMD_VOICE_OUTPUT_FLAGS_OFFSET) & MCMD_VOICE_KEYOFF_OUTPUT_FLAG) ==
             MCMD_VOICE_KEYOFF_OUTPUT_FLAG)) {
            *(u16 *)(state + MCMD_VOICE_LOOP_COUNTER_OFFSET) = 0;
            return;
        }
    }
    if (flags & MCMD_LOOP_WAIT_FOR_INACTIVE_FLAG) {
        zero = 0;
        if (((*(u32 *)(state + MCMD_VOICE_INPUT_FLAGS_OFFSET) & zero) == zero) &&
            ((*(u32 *)(state + MCMD_VOICE_OUTPUT_FLAGS_OFFSET) & MCMD_VOICE_ACTIVE_OUTPUT_FLAG) ==
             zero)) {
            if (hwIsActive(*(u8 *)(state + MCMD_VOICE_ID_OFFSET)) == 0) {
                *(u16 *)(state + MCMD_VOICE_LOOP_COUNTER_OFFSET) = zero;
                return;
            }
        }
    }
    *(int *)(state + MCMD_VOICE_PLAY_PTR_OFFSET) =
        *(int *)(state + 0x34) + ((*(u32 *)(params + 4) & 0xffff) << 3);
}
