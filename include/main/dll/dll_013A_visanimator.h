#ifndef MAIN_DLL_DLL_013A_VISANIMATOR_H_
#define MAIN_DLL_DLL_013A_VISANIMATOR_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/dll/visanimatorstate_struct.h"

typedef struct VisAnimatorPlacement
{
    ObjPlacement base;
    s16 gateGameBit;
    u8 pad1A;
    s8 initialVisibilityBit;
    u8 gateBitIndex;
    u8 pad1D[0xb];
} VisAnimatorPlacement;

STATIC_ASSERT(offsetof(VisAnimatorPlacement, gateGameBit) == 0x18);
STATIC_ASSERT(offsetof(VisAnimatorPlacement, initialVisibilityBit) == 0x1b);
STATIC_ASSERT(offsetof(VisAnimatorPlacement, gateBitIndex) == 0x1c);
STATIC_ASSERT(sizeof(VisAnimatorPlacement) == 0x28);

#define VISANIMATOR_FLAG_REFRESH_PENDING 1

int VisAnimator_getExtraSize(void);
int VisAnimator_getObjectTypeId(void);
void VisAnimator_free(void);
void VisAnimator_render(void);
void VisAnimator_hitDetect(void);
void VisAnimator_update(GameObject* obj);
void VisAnimator_init(GameObject* obj, VisAnimatorPlacement* placement);
void VisAnimator_release(void);
void VisAnimator_initialise(void);

extern ObjectDescriptor gVisAnimatorObjDescriptor;

#endif /* MAIN_DLL_DLL_013A_VISANIMATOR_H_ */
