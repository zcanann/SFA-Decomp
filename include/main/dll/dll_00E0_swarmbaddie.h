#ifndef MAIN_DLL_DLL_00E0_SWARMBADDIE_H_
#define MAIN_DLL_DLL_00E0_SWARMBADDIE_H_

#include "types.h"
#include "main/game_object.h"
#include "main/dll/swarmbaddiestate_struct.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

typedef struct SwarmBaddiePlacement
{
    ObjPlacement base;
    u8 unk18;
    s8 chaseRadiusScale;
    s16 curveStepParam;
} SwarmBaddiePlacement;

STATIC_ASSERT(sizeof(SwarmBaddiePlacement) == 0x1C);
STATIC_ASSERT(offsetof(SwarmBaddiePlacement, base) == 0x0);
STATIC_ASSERT(offsetof(SwarmBaddiePlacement, chaseRadiusScale) == 0x19);
STATIC_ASSERT(offsetof(SwarmBaddiePlacement, curveStepParam) == 0x1A);

extern ObjectDescriptor gSwarmBaddieObjDescriptor;

void fn_8014EE8C(GameObject* obj, SwarmBaddieState* state);
int SwarmBaddie_getExtraSize(void);
int SwarmBaddie_getObjectTypeId(void);
void SwarmBaddie_free(GameObject* obj);
void SwarmBaddie_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void SwarmBaddie_hitDetect(void);
void SwarmBaddie_update(GameObject* obj);
void SwarmBaddie_init(GameObject* obj, SwarmBaddiePlacement* placement, int initialised);
void SwarmBaddie_release(void);
void SwarmBaddie_initialise(void);

#endif /* MAIN_DLL_DLL_00E0_SWARMBADDIE_H_ */
