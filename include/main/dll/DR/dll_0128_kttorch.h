#ifndef MAIN_DLL_DR_DLL_0128_KTTORCH_H_
#define MAIN_DLL_DR_DLL_0128_KTTORCH_H_

#include "global.h"
#include "main/game_object.h"
#include "ghidra_import.h"

typedef struct KtTorchPlacement
{
    u8 pad0[0x18 - 0x0];
    u8 modelBankIndex; /* 0x18: model bank, clamped to modelCount */
    u8 startMove;      /* 0x19: initial anim move index */
    u8 moveStartSpeed; /* 0x1A: initial move speed factor */
    u8 animSpeed;      /* 0x1B */
    u8 flameScale;     /* 0x1C: flame scale byte, clamped to a floor */
    u8 swayRotPacked;  /* 0x1D: low 6 bits seed the swaying rotation */
    u8 pad1E[0x20 - 0x1E];
    s16 visGameBit; /* 0x20: -1 disables, else gates visibility */
} KtTorchPlacement;

STATIC_ASSERT(offsetof(KtTorchPlacement, animSpeed) == 0x1B);
STATIC_ASSERT(offsetof(KtTorchPlacement, visGameBit) == 0x20);
STATIC_ASSERT(sizeof(KtTorchPlacement) == 0x22);

int KT_Torch_getExtraSize(void);
int KT_Torch_getObjectTypeId(void);
void KT_Torch_free(void);
void KT_Torch_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void KT_Torch_hitDetect(void);
void KT_Torch_update(GameObject* obj);
void KT_Torch_init(GameObject* obj, int placement);
void KT_Torch_release(void);
void KT_Torch_initialise(void);

#endif /* MAIN_DLL_DR_DLL_0128_KTTORCH_H_ */
