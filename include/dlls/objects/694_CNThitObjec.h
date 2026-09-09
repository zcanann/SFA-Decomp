#ifndef DLLS_OBJECTS_694_CNTHITOBJEC_H_
#define DLLS_OBJECTS_694_CNTHITOBJEC_H_

#include "global.h"
#include "game/objects/object_fwd.h"
#include "dlls/object_descriptor.h"
#include "game/objects/object_setup.h"
#include "main/objseq.h"

#define CNTHIT_OBJECT_ID 0x6CF

typedef struct CntHitObjectFlags {
    u8 disabled : 1;
    u8 unknown : 7;
} CntHitObjectFlags;

/* cnthitobjec_getExtraSize returns the required 12-byte state size. */
typedef struct CntHitObjectState {
    int remainingHealth;
    int* allowedHitPriorities;
    u8 allowedHitPriorityCount;
    CntHitObjectFlags flags;
    u8 unknown0A[0xC - 0xA];
} CntHitObjectState;

/* Reader through +0x21; EN serialized extent is not established. Secondary
 * EN rev1 / JP records are 0x24 bytes. Do not allocate or copy using sizeof. */
typedef struct CntHitObjectPlacementPrefix {
    ObjPlacement base;
    s8 hitPriorityProfile;
    u8 mode;
    s16 startHealth;
    union {
        struct {
            s16 rotationX;
        } visible;
        struct {
            s16 radiusAndExplosionScale;
        } hidden;
    } modeParam;
    s16 doneGameBit;
    s16 startGameBit;
} CntHitObjectPlacementPrefix;

/* The descriptor advertises ten callbacks; its final word has no proven use. */
typedef struct CntHitObjectDescriptor {
    ObjectDescriptor descriptor;
    u32 unknown38;
} CntHitObjectDescriptor;

typedef struct CntHitObjectProfileCounts {
    u8 counts[3];
    u8 unknown03;
} CntHitObjectProfileCounts;

STATIC_ASSERT(offsetof(CntHitObjectState, allowedHitPriorities) == 0x04);
STATIC_ASSERT(offsetof(CntHitObjectState, allowedHitPriorityCount) == 0x08);
STATIC_ASSERT(offsetof(CntHitObjectState, flags) == 0x09);
STATIC_ASSERT(sizeof(CntHitObjectState) == 0x0C);
STATIC_ASSERT(offsetof(CntHitObjectPlacementPrefix, hitPriorityProfile) == 0x18);
STATIC_ASSERT(offsetof(CntHitObjectPlacementPrefix, mode) == 0x19);
STATIC_ASSERT(offsetof(CntHitObjectPlacementPrefix, startHealth) == 0x1A);
STATIC_ASSERT(offsetof(CntHitObjectPlacementPrefix, modeParam.visible.rotationX) == 0x1C);
STATIC_ASSERT(offsetof(CntHitObjectPlacementPrefix, modeParam.hidden.radiusAndExplosionScale) == 0x1C);
STATIC_ASSERT(offsetof(CntHitObjectPlacementPrefix, doneGameBit) == 0x1E);
STATIC_ASSERT(offsetof(CntHitObjectPlacementPrefix, startGameBit) == 0x20);
STATIC_ASSERT(offsetof(CntHitObjectState, remainingHealth) == 0x00);
STATIC_ASSERT(offsetof(CntHitObjectState, unknown0A) == 0x0A);
STATIC_ASSERT(sizeof(CntHitObjectFlags) == 1);
STATIC_ASSERT(offsetof(CntHitObjectPlacementPrefix, base) == 0x00);
STATIC_ASSERT(offsetof(CntHitObjectDescriptor, descriptor) == 0x00);
STATIC_ASSERT(offsetof(CntHitObjectDescriptor, unknown38) == 0x38);
STATIC_ASSERT(sizeof(CntHitObjectDescriptor) == 0x3C);
STATIC_ASSERT(offsetof(CntHitObjectProfileCounts, counts) == 0x00);
STATIC_ASSERT(offsetof(CntHitObjectProfileCounts, unknown03) == 0x03);
STATIC_ASSERT(sizeof(CntHitObjectProfileCounts) == 4);

extern CntHitObjectDescriptor gCNThitObjecObjDescriptor;

int cnthitobjec_getExtraSize(void);
int cnthitobjec_getObjectTypeId(void);
void cnthitobjec_free(void);
void cnthitobjec_release(void);
void cnthitobjec_initialise(void);
void cnthitobjec_render(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale);
int cnthitobjec_SeqFn(GameObject* obj, int unused, ObjSeqState* event);
void cnthitobjec_hitDetect(GameObject* obj);
void cnthitobjec_init(GameObject* obj, CntHitObjectPlacementPrefix* setup);
void cnthitobjec_update(GameObject* obj);
int mcupgrade_SeqFn(GameObject* obj, int unused, ObjSeqState* event);

#endif
