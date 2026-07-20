#ifndef MAIN_DLL_CF_DLL_012E_CFLIGHTWALL_H_
#define MAIN_DLL_CF_DLL_012E_CFLIGHTWALL_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

typedef struct CFLightWallSetup
{
    ObjPlacement base;
    u8 rotZ;
    u8 rotY;
    u8 rotX;
    u8 scale;
} CFLightWallSetup;

STATIC_ASSERT(offsetof(CFLightWallSetup, rotZ) == 0x18);
STATIC_ASSERT(offsetof(CFLightWallSetup, rotY) == 0x19);
STATIC_ASSERT(offsetof(CFLightWallSetup, rotX) == 0x1a);
STATIC_ASSERT(offsetof(CFLightWallSetup, scale) == 0x1b);

int CFLightWall_getExtraSize(void);
int CFLightWall_getObjectTypeId(void);
void CFLightWall_free(void);
void CFLightWall_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void CFLightWall_hitDetect(void);
void CFLightWall_update(void);
void CFLightWall_init(GameObject* obj, CFLightWallSetup* setup);
void CFLightWall_release(void);
void CFLightWall_initialise(void);

extern ObjectDescriptor gCflightwallObjDescriptor;

#endif /* MAIN_DLL_CF_DLL_012E_CFLIGHTWALL_H_ */
