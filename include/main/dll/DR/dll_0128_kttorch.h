#ifndef MAIN_DLL_DR_DLL_0128_KTTORCH_H_
#define MAIN_DLL_DR_DLL_0128_KTTORCH_H_

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct KtTorchPlacement
{
    ObjPlacement base;
    u8 modelBankIndex; /* 0x18: model bank, clamped to modelCount */
    u8 startMove;      /* 0x19: initial anim move index */
    u8 moveStartSpeed; /* 0x1A: initial move speed factor */
    u8 animSpeed;      /* 0x1B */
    u8 flameScale;     /* 0x1C: flame scale byte, clamped to a floor */
    u8 swayRotPacked;  /* 0x1D: low 6 bits seed the swaying rotation */
    u8 pad1E[0x20 - 0x1E];
    s16 visGameBit; /* 0x20: -1 disables, else gates visibility */
} KtTorchPlacement;

STATIC_ASSERT(offsetof(KtTorchPlacement, modelBankIndex) == 0x18);
STATIC_ASSERT(offsetof(KtTorchPlacement, animSpeed) == 0x1b);
STATIC_ASSERT(offsetof(KtTorchPlacement, flameScale) == 0x1c);
STATIC_ASSERT(offsetof(KtTorchPlacement, visGameBit) == 0x20);
STATIC_ASSERT(sizeof(KtTorchPlacement) == 0x24);

int KT_Torch_getExtraSize(void);
int KT_Torch_getObjectTypeId(void);
void KT_Torch_free(void);
void KT_Torch_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void KT_Torch_hitDetect(void);
void KT_Torch_update(GameObject* obj);
void KT_Torch_init(GameObject* obj, KtTorchPlacement* placement);
void KT_Torch_release(void);
void KT_Torch_initialise(void);

extern ObjectDescriptor gKT_TorchObjDescriptor;

#endif /* MAIN_DLL_DR_DLL_0128_KTTORCH_H_ */
