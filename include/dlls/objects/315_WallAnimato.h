#ifndef DLLS_OBJECTS_315_WALLANIMATO_H_
#define DLLS_OBJECTS_315_WALLANIMATO_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

typedef enum WallAnimatorObjectGroup {
    WALL_ANIMATOR_GROUP_CLIMBABLE = 0x23,
} WallAnimatorObjectGroup;

typedef struct WallAnimatorPlacement {
    ObjPlacement base;      /* 0x00 */
    s16 completionBit;      /* 0x18 */
    u8 pad1A[2];            /* 0x1A */
    s16 digParticleVariant; /* 0x1C */
    u8 pad1E[6];            /* 0x1E */
    s16 initialRotX;        /* 0x24 */
    u8 pad26[2];            /* 0x26 */
} WallAnimatorPlacement;

/* WallAnimator_getExtraSize proves the complete 0x08-byte allocation. */
typedef struct WallAnimatorState {
    s32 timer; /* 0x00 */
    struct {
        u8 complete : 1; /* 0x80 */
        u8 unused : 7;
    }; /* 0x04 */
    u8 pad05[3]; /* 0x05 */
} WallAnimatorState;

STATIC_ASSERT(offsetof(WallAnimatorPlacement, base) == 0x00);
STATIC_ASSERT(offsetof(WallAnimatorPlacement, completionBit) == 0x18);
STATIC_ASSERT(offsetof(WallAnimatorPlacement, pad1A) == 0x1A);
STATIC_ASSERT(offsetof(WallAnimatorPlacement, digParticleVariant) == 0x1C);
STATIC_ASSERT(offsetof(WallAnimatorPlacement, pad1E) == 0x1E);
STATIC_ASSERT(offsetof(WallAnimatorPlacement, initialRotX) == 0x24);
STATIC_ASSERT(offsetof(WallAnimatorPlacement, pad26) == 0x26);
STATIC_ASSERT(sizeof(WallAnimatorPlacement) == 0x28);

STATIC_ASSERT(offsetof(WallAnimatorState, timer) == 0x00);
STATIC_ASSERT(offsetof(WallAnimatorState, pad05) == 0x05);
STATIC_ASSERT(sizeof(WallAnimatorState) == 0x08);

u8 WallAnimator_getDigParticleVariant(GameObject* obj);
/* gWallAnimatorObjDescriptor from slot02 onwards: the export table other
   objects reach through obj->anim.dll. */
typedef struct WallAnimatorInterface {
    void* pad00[8];
    f32 (*applyImpact)(GameObject* obj, GameObject* target);
    u8 (*isComplete)(GameObject* obj);
    u8 (*getDigParticleVariant)(GameObject* obj);
} WallAnimatorInterface;

#define WALL_ANIMATOR_INTERFACE(wall) ((WallAnimatorInterface*)*((GameObject*)(wall))->anim.dll)

STATIC_ASSERT(offsetof(WallAnimatorInterface, applyImpact) == 0x20);
STATIC_ASSERT(offsetof(WallAnimatorInterface, isComplete) == 0x24);
STATIC_ASSERT(offsetof(WallAnimatorInterface, getDigParticleVariant) == 0x28);

u8 WallAnimator_isComplete(GameObject* obj);
f32 WallAnimator_applyImpact(GameObject* obj, GameObject* target);
int WallAnimator_getExtraSize(void);
void WallAnimator_free(GameObject* obj);
void WallAnimator_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
void WallAnimator_update(GameObject* obj);
void WallAnimator_init(GameObject* objAddress, WallAnimatorPlacement* placement);

extern ObjectDescriptor14 gWallAnimatorObjDescriptor;

#endif /* DLLS_OBJECTS_315_WALLANIMATO_H_ */
