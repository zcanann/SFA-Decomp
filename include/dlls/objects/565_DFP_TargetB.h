#ifndef DLLS_OBJECTS_565_DFP_TARGETB_H_
#define DLLS_OBJECTS_565_DFP_TARGETB_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "main/vec_types.h"

/*
 * Placement/def record the map loader hands to dfptargetblock_init. Embeds the
 * common ObjPlacement head, then the block's class-specific SFX gamebit ids
 * (def+0x1E / def+0x20) read in dfptargetblock_init.
 */
typedef struct DfpTargetBlockPlacement {
    ObjPlacement base;     /* 0x00: common placement head */
    u8 pad18[0x1E - 0x18]; /* 0x18 */
    s16 completionSfxId;   /* 0x1E */
    s16 stateSfxId;        /* 0x20 */
} DfpTargetBlockPlacement;

STATIC_ASSERT(offsetof(DfpTargetBlockPlacement, completionSfxId) == 0x1E);
STATIC_ASSERT(offsetof(DfpTargetBlockPlacement, stateSfxId) == 0x20);

typedef struct DfpTargetBlockState {
    void* pathState;
    Vec3f floorPoints[8];
    s16 stateSfxId;
    s16 completionSfxId;
    s8 floorPointCount;
    u8 mode;
    u8 stateSfxReady;
    u8 completionSfxReady;
} DfpTargetBlockState;

STATIC_ASSERT(offsetof(DfpTargetBlockState, floorPoints) == 0x04);
STATIC_ASSERT(offsetof(DfpTargetBlockState, stateSfxId) == 0x64);
STATIC_ASSERT(offsetof(DfpTargetBlockState, completionSfxId) == 0x66);
STATIC_ASSERT(offsetof(DfpTargetBlockState, floorPointCount) == 0x68);
STATIC_ASSERT(offsetof(DfpTargetBlockState, mode) == 0x69);
STATIC_ASSERT(sizeof(DfpTargetBlockState) == 0x6C);

void dfptargetblock_update(GameObject* obj);
void dfptargetblock_resolveCollisionPoints(GameObject* obj, DfpTargetBlockState* state);
void dfptargetblock_init(GameObject* obj, DfpTargetBlockPlacement* placement);
int dfptargetblock_getExtraSize(void);
int dfptargetblock_getObjectTypeId(void);
void dfptargetblock_free(GameObject* obj);
void dfptargetblock_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dfptargetblock_hitDetect(GameObject* obj);
void dfptargetblock_release(void);
void dfptargetblock_initialise(void);
extern ObjectDescriptor10WithPadding gDfptargetblockObjDescriptor;

#endif /* DLLS_OBJECTS_565_DFP_TARGETB_H_ */
