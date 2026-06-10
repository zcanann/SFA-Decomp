#ifndef MAIN_DLL_COLLECTIBLE_STATE_H_
#define MAIN_DLL_COLLECTIBLE_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* CollectibleState - the obj+0xB8 extra record of the collectible/
 * magicdust family, censused from texframeanimator.c (which contains
 * that family despite its filename - the real texframeanimator_*
 * symbols live in MMP_asteroid.c; file rename parked as a repo-owner
 * proposal). Field widths
 * mirror the observed deref widths; unobserved ranges are padded. The
 * span covers every observed access - the true allocation may be larger.
 */
typedef struct CollectibleState {
    u8 unk0[0x4 - 0x0];
    f32 unk4;
    u8 unk8[0xC - 0x8];
    u8 unkC;
    u8 unkD;
    u8 unkE[0xF - 0xE];
    u8 unkF;
    s16 hideGameBit;
    u8 unk12[0x14 - 0x12];
    s16 unk14;
    u8 unk16[0x18 - 0x16];
    s32 unk18;
    u8 unk1C[0x1D - 0x1C];
    u8 unk1D;
    u8 gameBit1E;
    u8 unk1F[0x20 - 0x1F];
    s32 unk20;
    f32 basePosX;
    f32 basePosY;
    f32 basePosZ;
    u8 unk30[0x36 - 0x30];
    u8 unk36;
    u8 unk37[0x38 - 0x37];
    u8 unk38;
    u8 unk39;
    u8 unk3A;
    u8 unk3B[0x3E - 0x3B];
    u8 unk3E;
    u8 unk3F[0x40 - 0x3F];
    f32 unk40;
    f32 unk44;
    u8 unk48[0x4C - 0x48];
} CollectibleState;

#endif /* MAIN_DLL_COLLECTIBLE_STATE_H_ */
