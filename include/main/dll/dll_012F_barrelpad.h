#ifndef MAIN_DLL_DLL_012F_BARRELPAD_H_
#define MAIN_DLL_DLL_012F_BARRELPAD_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

typedef struct BarrelPadSetup
{
    ObjPlacement base;
    u8 rotZ;
    u8 rotY;
    u8 rotX;
    u8 scale;
} BarrelPadSetup;

typedef struct BarrelPadParticleArgs
{
    u8 pad00[0xc];
    f32 offset[3];
} BarrelPadParticleArgs;

STATIC_ASSERT(offsetof(BarrelPadSetup, rotZ) == 0x18);
STATIC_ASSERT(offsetof(BarrelPadSetup, rotY) == 0x19);
STATIC_ASSERT(offsetof(BarrelPadSetup, rotX) == 0x1a);
STATIC_ASSERT(offsetof(BarrelPadSetup, scale) == 0x1b);
STATIC_ASSERT(sizeof(BarrelPadSetup) == 0x1c);
STATIC_ASSERT(offsetof(BarrelPadParticleArgs, offset) == 0x0c);
STATIC_ASSERT(sizeof(BarrelPadParticleArgs) == 0x18);

int BarrelPad_getExtraSize(void);
int BarrelPad_getObjectTypeId(void);
void BarrelPad_free(void);
void BarrelPad_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void BarrelPad_hitDetect(void);
void BarrelPad_update(GameObject* obj);
void BarrelPad_init(GameObject* obj, BarrelPadSetup* setup);
void BarrelPad_release(void);
void BarrelPad_initialise(void);

extern ObjectDescriptor gBarrelPadObjDescriptor;

#endif /* MAIN_DLL_DLL_012F_BARRELPAD_H_ */
