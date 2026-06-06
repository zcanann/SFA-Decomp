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
    f32 unk4;
    f32 unk8;
    u8 unkC[0x10 - 0xC];
    f32 unk10;
    f32 unk14;
    f32 unk18;
    f32 unk1C;
    f32 unk20;
    f32 unk24;
    f32 unk28;
    u8 unk2C[0x38 - 0x2C];
    u16 unk38;
    u8 unk3A;
    u8 unk3B[0x3C - 0x3B];
    f32 unk3C;
    f32 unk40;
    f32 unk44;
    u8 unk48[0x54 - 0x48];
    f32 unk54;
    u8 unk58[0x5C - 0x58];
} CrackAnimState;

#endif /* MAIN_DLL_CRACKANIM_STATE_H_ */
