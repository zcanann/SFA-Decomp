#ifndef MAIN_DLL_IM_DLL_0170_IMSPACERING_H_
#define MAIN_DLL_IM_DLL_0170_IMSPACERING_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

typedef struct IMSpaceRingPlacement
{
    ObjPlacement base;
    s8 initialRotX;
    u8 pad19;
    s16 spinSpeed;
    s16 tiltSpeed;
    u8 pad1E[0x24 - 0x1E];
} IMSpaceRingPlacement;

STATIC_ASSERT(offsetof(IMSpaceRingPlacement, initialRotX) == 0x18);
STATIC_ASSERT(offsetof(IMSpaceRingPlacement, spinSpeed) == 0x1A);
STATIC_ASSERT(offsetof(IMSpaceRingPlacement, tiltSpeed) == 0x1C);
STATIC_ASSERT(sizeof(IMSpaceRingPlacement) == 0x24);

extern GameObject* gSpaceRingLeader;
extern ObjectDescriptor gIMSpaceRingObjDescriptor;

int IMSpaceRing_getExtraSize(void);
int IMSpaceRing_getObjectTypeId(void);
void IMSpaceRing_free(GameObject* obj);
void IMSpaceRing_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible);
void IMSpaceRing_hitDetect(void);
void IMSpaceRing_update(GameObject* obj);
void IMSpaceRing_init(GameObject* obj, IMSpaceRingPlacement* placement);
void IMSpaceRing_release(void);
void IMSpaceRing_initialise(void);

#endif
