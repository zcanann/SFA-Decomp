#ifndef DLLS_OBJECTS_312_GROUNDANIMA_H_
#define DLLS_OBJECTS_312_GROUNDANIMA_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

typedef enum GroundAnimatorStateFlag {
    GROUND_ANIMATOR_STATE_ON_MAP = 0x01,
    GROUND_ANIMATOR_STATE_COMPLETE = 0x02,
    GROUND_ANIMATOR_STATE_PRESSED = 0x04,
} GroundAnimatorStateFlag;

typedef struct GroundAnimatorPlacement {
    ObjPlacement base;   /* 0x00 */
    s16 sunkGameBit;     /* 0x18 */
    s16 enableGameBit;   /* 0x1A */
    u8 pad1C[2];         /* 0x1C */
    s16 magicCaveId;     /* 0x1E */
    u8 maxSinkDepth;     /* 0x20: multiplied by 100 */
    u8 sfxIndex;         /* 0x21 */
    u8 disableAutoLink;  /* 0x22 */
    u8 pad23[2];         /* 0x23 */
    u8 animatorId;       /* 0x25: polygon-group type to animate */
    u8 falloffRadius;    /* 0x26 */
    u8 collectibleDepth; /* 0x27 */
} GroundAnimatorPlacement;

/* GroundAnimator_getExtraSize proves the complete 0x30-byte allocation. */
typedef struct GroundAnimatorState {
    f32* vertexWeights;          /* 0x00: displacement weight per animated vertex */
    s16* baseVertexHeights;      /* 0x04: original height per animated vertex */
    GameObject* collectible;     /* 0x08: buried collectible */
    f32 sinkDepth;               /* 0x0C */
    f32 previousSinkDepth;       /* 0x10 */
    f32 falloffRadius;           /* 0x14 */
    f32 collectibleDepth;        /* 0x18 */
    s16 animatedGroupIndices[6]; /* 0x1C: matching polygon-group indices */
    s16 animatedVertexCount;     /* 0x28 */
    u8 animatedGroupCount;       /* 0x2A */
    u8 magicCaveId;              /* 0x2B */
    u8 vertexUpdateFrames;       /* 0x2C */
    u8 flags;                    /* 0x2D: GroundAnimatorStateFlag */
    u8 pad2E[2];                 /* 0x2E */
} GroundAnimatorState;

STATIC_ASSERT(offsetof(GroundAnimatorPlacement, base) == 0x00);
STATIC_ASSERT(offsetof(GroundAnimatorPlacement, sunkGameBit) == 0x18);
STATIC_ASSERT(offsetof(GroundAnimatorPlacement, enableGameBit) == 0x1A);
STATIC_ASSERT(offsetof(GroundAnimatorPlacement, pad1C) == 0x1C);
STATIC_ASSERT(offsetof(GroundAnimatorPlacement, magicCaveId) == 0x1E);
STATIC_ASSERT(offsetof(GroundAnimatorPlacement, maxSinkDepth) == 0x20);
STATIC_ASSERT(offsetof(GroundAnimatorPlacement, sfxIndex) == 0x21);
STATIC_ASSERT(offsetof(GroundAnimatorPlacement, disableAutoLink) == 0x22);
STATIC_ASSERT(offsetof(GroundAnimatorPlacement, pad23) == 0x23);
STATIC_ASSERT(offsetof(GroundAnimatorPlacement, animatorId) == 0x25);
STATIC_ASSERT(offsetof(GroundAnimatorPlacement, falloffRadius) == 0x26);
STATIC_ASSERT(offsetof(GroundAnimatorPlacement, collectibleDepth) == 0x27);
STATIC_ASSERT(sizeof(GroundAnimatorPlacement) == 0x28);

STATIC_ASSERT(offsetof(GroundAnimatorState, vertexWeights) == 0x00);
STATIC_ASSERT(offsetof(GroundAnimatorState, baseVertexHeights) == 0x04);
STATIC_ASSERT(offsetof(GroundAnimatorState, collectible) == 0x08);
STATIC_ASSERT(offsetof(GroundAnimatorState, sinkDepth) == 0x0C);
STATIC_ASSERT(offsetof(GroundAnimatorState, previousSinkDepth) == 0x10);
STATIC_ASSERT(offsetof(GroundAnimatorState, falloffRadius) == 0x14);
STATIC_ASSERT(offsetof(GroundAnimatorState, collectibleDepth) == 0x18);
STATIC_ASSERT(offsetof(GroundAnimatorState, animatedGroupIndices) == 0x1C);
STATIC_ASSERT(offsetof(GroundAnimatorState, animatedVertexCount) == 0x28);
STATIC_ASSERT(offsetof(GroundAnimatorState, animatedGroupCount) == 0x2A);
STATIC_ASSERT(offsetof(GroundAnimatorState, magicCaveId) == 0x2B);
STATIC_ASSERT(offsetof(GroundAnimatorState, vertexUpdateFrames) == 0x2C);
STATIC_ASSERT(offsetof(GroundAnimatorState, flags) == 0x2D);
STATIC_ASSERT(offsetof(GroundAnimatorState, pad2E) == 0x2E);
STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);

u8 GroundAnimator_getMagicCaveIndex(GameObject* obj);
/* gGroundAnimatorObjDescriptor from slot02 onwards: the export table Tricky
   reaches through obj->anim.dll while digging. */
typedef struct GroundAnimatorInterface {
    void* pad00[8];
    f32 (*applyPress)(GameObject* obj, GameObject* sidekick);
    u8 (*isFullySunk)(GameObject* obj);
    u8 (*getMagicCaveIndex)(GameObject* obj);
} GroundAnimatorInterface;

#define GROUND_ANIMATOR_INTERFACE(digSite) ((GroundAnimatorInterface*)*((GameObject*)(digSite))->anim.dll)

STATIC_ASSERT(offsetof(GroundAnimatorInterface, applyPress) == 0x20);
STATIC_ASSERT(offsetof(GroundAnimatorInterface, isFullySunk) == 0x24);
STATIC_ASSERT(offsetof(GroundAnimatorInterface, getMagicCaveIndex) == 0x28);
STATIC_ASSERT(sizeof(GroundAnimatorInterface) == 0x2C);

u8 GroundAnimator_isFullySunk(GameObject* obj);
f32 GroundAnimator_applyPress(GameObject* obj, GameObject* sidekick);
int GroundAnimator_getExtraSize(void);
void GroundAnimator_free(GameObject* obj, int onlySelf);
void GroundAnimator_render(GameObject* obj, int gdl, int mtxs, int vtxs, int pols, s8 visibility);
void GroundAnimator_update(GameObject* obj);
void GroundAnimator_init(GameObject* obj, GroundAnimatorPlacement* placement);

extern ObjectDescriptor14 gGroundAnimatorObjDescriptor;

#endif /* DLLS_OBJECTS_312_GROUNDANIMA_H_ */
