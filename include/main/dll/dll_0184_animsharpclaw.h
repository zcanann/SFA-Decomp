#ifndef MAIN_DLL_DLL_0184_ANIMSHARPCLAW_H_
#define MAIN_DLL_DLL_0184_ANIMSHARPCLAW_H_

#include "global.h"
#include "main/objanim_update.h"

typedef struct AnimsharpclawPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 linkIndex;
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
} AnimsharpclawPlacement;

typedef struct AnimsharpclawState
{
    u8 pad0[0x24 - 0x0];
    f32 dampingFactor; /* 0x24: base/(base + placement[0x24]) smoothing coefficient */
    s32 unk28;
    u8 pad2C[0x57 - 0x2C];
    u8 kind;
    u8 pad58[0x6A - 0x58];
    s16 unk6A;
    u8 pad6C[0x6E - 0x6C];
    s16 unk6E;
    u8 pad70[0x94 - 0x70];
    s32 unk94;
    s32 unk98;
    u8 pad9C[0x140 - 0x9C];
} AnimsharpclawState;

int fn_801A8F88(int obj, ObjAnimUpdateState* animUpdate);
int animsharpclaw_getExtraSize(void);
int animsharpclaw_getObjectTypeId(void);
void animsharpclaw_free(int obj);
void animsharpclaw_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void animsharpclaw_hitDetect(void);
void animsharpclaw_update(int* obj);
void animsharpclaw_init(int* obj, u8* init);
void animsharpclaw_release(void);
void animsharpclaw_initialise(void);

#endif /* MAIN_DLL_DLL_0184_ANIMSHARPCLAW_H_ */
