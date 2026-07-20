#ifndef MAIN_DLL_CF_DLL_0162_CFMAGICWALL_H_
#define MAIN_DLL_CF_DLL_0162_CFMAGICWALL_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

typedef struct CfMagicWallSetup
{
    ObjPlacement base;
    s8 rotX;
    u8 pad19;
    s16 fadeRange;
    u8 pad1C[4];
    s16 visibleGameBit;
    u8 pad22[0x28 - 0x22];
} CfMagicWallSetup;

STATIC_ASSERT(offsetof(CfMagicWallSetup, rotX) == 0x18);
STATIC_ASSERT(offsetof(CfMagicWallSetup, fadeRange) == 0x1A);
STATIC_ASSERT(offsetof(CfMagicWallSetup, visibleGameBit) == 0x20);

int cfmagicwall_getExtraSize(void);
int cfmagicwall_getObjectTypeId(void);
void cfmagicwall_free(void);
void cfmagicwall_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void cfmagicwall_hitDetect(void);
void cfmagicwall_update(GameObject* obj);
void cfmagicwall_init(GameObject* obj, CfMagicWallSetup* setup);
void cfmagicwall_release(void);
void cfmagicwall_initialise(void);

extern ObjectDescriptor gCFMagicWallObjDescriptor;

#endif /* MAIN_DLL_CF_DLL_0162_CFMAGICWALL_H_ */
