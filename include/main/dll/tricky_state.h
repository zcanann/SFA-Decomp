#ifndef MAIN_DLL_TRICKY_STATE_H_
#define MAIN_DLL_TRICKY_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/*
 * TrickyState - the obj+0xB8 extra record for the Tricky sidekick handlers
 * in grenade.c (trickyFn_* / trickyFoodFn_* / trickyFlameFn_* take it as
 * "state"). Field widths mirror the deref widths observed in grenade.c;
 * unobserved ranges are padded. 0x840 covers every observed access - the
 * true allocation may be larger.
 */
typedef struct TrickyState {
    u8 unk0[0x4 - 0x0];
    int unk4;
    u8 unk8[0xA - 0x8];
    u8 unkA;
    u8 unkB[0xD - 0xB];
    s8 unkD;
    u8 unkE[0x10 - 0xE];
    f32 unk10;
    f32 unk14;
    u8 unk18[0x24 - 0x18];
    u8 *unk24;
    u8 *unk28;
    f32 unk2C;
    f32 unk30;
    u8 unk34[0x54 - 0x34];
    u32 unk54;
    u8 unk58;
    u8 unk59[0xD2 - 0x59];
    u16 unkD2;
    u8 unkD4[0xE0 - 0xD4];
    f32 unkE0;
    f32 unkE4;
    f32 unkE8;
    u8 unkEC[0x2AC - 0xEC];
    f32 unk2AC;
    f32 unk2B0;
    f32 unk2B4;
    u8 unk2B8[0x700 - 0x2B8];
    u8 *unk700;
    u8 *unk704;
    u8 *unk708;
    u8 *unk70C;
    f32 unk710;
    u8 unk714[0x71C - 0x714];
    f32 unk71C;
    f32 unk720;
    u8 unk724[0x728 - 0x724];
    u8 unk728;
    u8 unk729[0x72C - 0x729];
    f32 unk72C;
    u32 unk730;
    f32 unk734;
    f32 unk738;
    f32 unk73C;
    f32 unk740;
    u8 unk744[0x79C - 0x744];
    f32 unk79C;
    u8 unk7A0[0x7A8 - 0x7A0];
    u8 *unk7A8;
    u8 unk7AC[0x7B0 - 0x7AC];
    u8 *unk7B0;
    u8 unk7B4[0x7B8 - 0x7B4];
    u8 *unk7B8;
    u8 unk7BC[0x7C0 - 0x7BC];
    f32 unk7C0;
    f32 unk7C4;
    f32 unk7C8;
    u8 unk7CC[0x7D4 - 0x7CC];
    u8 *unk7D4;
    u8 unk7D8[0x82D - 0x7D8];
    u8 unk82D;
    u8 unk82E;
    u8 unk82F[0x838 - 0x82F];
    f32 unk838;
    u8 unk83C[0x840 - 0x83C];
} TrickyState;

STATIC_ASSERT(sizeof(TrickyState) == 0x840);
STATIC_ASSERT(offsetof(TrickyState, unk54) == 0x54);

#endif /* MAIN_DLL_TRICKY_STATE_H_ */
