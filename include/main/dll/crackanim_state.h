#ifndef MAIN_DLL_CRACKANIM_STATE_H_
#define MAIN_DLL_CRACKANIM_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* crackanim_state_GENERATED
 * CrackAnimState - the obj+0xB8 extra record observed in crackanim.c.
 * Field widths mirror the observed deref widths; unobserved ranges are
 * padded. The span covers every observed access - the true allocation
 * may be larger.
 */
typedef struct CrackAnimState {
    u32 unk0;
    f32 duration;
    f32 elapsed;
    u8 unkC[0x10 - 0xC];
    f32 stageEnd0;
    f32 stageEnd1;
    f32 stageEnd2;
    f32 stageEnd3;
    f32 fadeThreshold;
    f32 fallScale;
    f32 velY;
    u8 unk2C[0x38 - 0x2C];
    u16 healthRestore;
    u8 stage;
    u8 unk3B[0x3C - 0x3B];
    f32 extraAccel;
    f32 gravity;
    f32 bounceVel;
    u8 unk48[0x54 - 0x48];
    f32 fallBlendDivisor;
    u8 unk58[0x5C - 0x58];
} CrackAnimState;

#endif /* MAIN_DLL_CRACKANIM_STATE_H_ */
