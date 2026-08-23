#ifndef MAIN_DLL_DR_DLL_0254_KTFALLINGROCKS_H_
#define MAIN_DLL_DR_DLL_0254_KTFALLINGROCKS_H_

#include "game/objects/object.h"
#include "global.h"
#include "game/objects/object_setup.h"
#include "dlls/object_descriptor.h"

typedef struct KtfallingrocksPlacement
{
    ObjPlacement base;
    u8 pad18[0x20 - 0x18];
    u16 effectId; /* 0x20: particle effect id spawned per rock */
    u8 pad22[0x24 - 0x22];
    s16 triggerBit; /* 0x24: game bit; fires the burst then is cleared */
    u8 pad26[0x28 - 0x26];
} KtfallingrocksPlacement;

STATIC_ASSERT(offsetof(KtfallingrocksPlacement, effectId) == 0x20);
STATIC_ASSERT(offsetof(KtfallingrocksPlacement, triggerBit) == 0x24);
STATIC_ASSERT(sizeof(KtfallingrocksPlacement) == 0x28);

int ktfallingrocks_getExtraSize(void);
int ktfallingrocks_getObjectTypeId(void);
void ktfallingrocks_free(u8* obj);
void ktfallingrocks_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible);
void ktfallingrocks_hitDetect(void);
void ktfallingrocks_update(GameObject* obj);
void ktfallingrocks_init(GameObject* obj);
void ktfallingrocks_release(void);
void ktfallingrocks_initialise(void);

extern ObjectDescriptor gKtFallingrocksObjDescriptor;

#endif /* MAIN_DLL_DR_DLL_0254_KTFALLINGROCKS_H_ */
