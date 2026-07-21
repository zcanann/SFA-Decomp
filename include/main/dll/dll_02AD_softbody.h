#ifndef MAIN_DLL_DLL_02AD_SOFTBODY_H
#define MAIN_DLL_DLL_02AD_SOFTBODY_H

#include "global.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

typedef struct SoftBodySetup
{
    ObjPlacement base;
    u8 rotZ;
    u8 rotY;
    u8 rotX;
    u8 scale;
    u8 pad1C[3];
    u8 phaseDriverDisabled;
} SoftBodySetup;

STATIC_ASSERT(offsetof(SoftBodySetup, rotZ) == 0x18);
STATIC_ASSERT(offsetof(SoftBodySetup, scale) == 0x1b);
STATIC_ASSERT(offsetof(SoftBodySetup, phaseDriverDisabled) == 0x1f);
STATIC_ASSERT(sizeof(SoftBodySetup) == 0x20);

extern GameObject* gSoftBodyPhaseDriver;
extern f32 gSoftBodyFastPhase;
extern f32 gSoftBodySlowPhase;
extern ObjectDescriptor gSoftBodyObjDescriptor;

int SoftBody_getExtraSize(void);
int SoftBody_getObjectTypeId(void);
void SoftBody_free(GameObject* obj);
void SoftBody_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void SoftBody_hitDetect(void);
void SoftBody_init(GameObject* obj, SoftBodySetup* setup);
void SoftBody_update(GameObject* obj);
void SoftBody_release(void);
void SoftBody_initialise(void);

#endif
