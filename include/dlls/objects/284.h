#ifndef DLLS_OBJECTS_284_H_
#define DLLS_OBJECTS_284_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

#define STAFF_ACTIVATED_STATE_SIZE   0x24
#define STAFF_ACTIVATED_OBJECT_GROUP 0x41

#define STAFF_ACTIVATED_HIT_EFFECT_MODE  8
#define STAFF_ACTIVATED_HIT_EFFECT_RED   0xB4
#define STAFF_ACTIVATED_HIT_EFFECT_GREEN 0xF0
#define STAFF_ACTIVATED_HIT_EFFECT_BLUE  0xFF
#define STAFF_ACTIVATED_HIT_EFFECT_SFX   0x6F

typedef enum StaffActivatedMode {
    STAFF_ACTIVATED_MODE_ACTION = 0,
    STAFF_ACTIVATED_MODE_LIFT = 2,
    STAFF_ACTIVATED_MODE_HIT_REACTION = 3,
    STAFF_ACTIVATED_MODE_DAMAGE_FIRST = 4,
    STAFF_ACTIVATED_MODE_DAMAGE_SECOND = 5,
} StaffActivatedMode;

/* Only the accessed placement prefix is recovered; the complete retail width is not established. */
typedef struct StaffActivatedPlacement {
    ObjPlacement base; /* 0x00 */
    u8 rotationX;      /* 0x18: high byte of the initial X rotation */
    u8 unk19;          /* 0x19 */
    u8 pad1A[2];       /* 0x1A */
    u8 mode;           /* 0x1C */
    u8 sizeVariant;    /* 0x1D */
    union {
        u8 scarabObjectSet; /* Staff-action scarab object-set index */
        u8 hitReactionType; /* Landed-Arwing hit-reaction mode */
    }; /* 0x1E */
    union {
        u8 scarabCount;
        u8 debrisCount;
    }; /* 0x1F */
    u8 timedEventSeconds; /* 0x20 */
    u8 pad21;             /* 0x21 */
    union {
        s16 activeGameBit;
        s16 damagedGameBit;
        s16 siblingGameBit;
    }; /* 0x22 */
    union {
        s16 lockGameBit;
        s16 damageStateGameBit;
        s16 reactionCompleteGameBit;
    }; /* 0x24 */
} StaffActivatedPlacement;

typedef struct StaffActivatedFlags {
    u8 active : 1;
    u8 locked : 1;
    u8 gameBitMirror : 1;
    u8 unk4 : 1;
    u8 pad : 4;
} StaffActivatedFlags;

typedef struct StaffActivatedState {
    f32 targetX;               /* 0x00 */
    f32 targetZ;               /* 0x04 */
    u8 pad08[4];               /* 0x08 */
    s32 liftVelocity;          /* 0x0C */
    s32 previousLiftHeight;    /* 0x10 */
    s32 liftHeight;            /* 0x14 */
    s32 peakLiftHeight;        /* 0x18 */
    u8 liftReset;              /* 0x1C */
    StaffActivatedFlags flags; /* 0x1D */
    u8 pad1E[2];               /* 0x1E */
    f32 hitCooldown;           /* 0x20 */
} StaffActivatedState;

STATIC_ASSERT(offsetof(StaffActivatedPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(StaffActivatedPlacement, rotationX) == 0x18);
STATIC_ASSERT(offsetof(StaffActivatedPlacement, unk19) == 0x19);
STATIC_ASSERT(offsetof(StaffActivatedPlacement, pad1A) == 0x1A);
STATIC_ASSERT(offsetof(StaffActivatedPlacement, mode) == 0x1C);
STATIC_ASSERT(offsetof(StaffActivatedPlacement, sizeVariant) == 0x1D);
STATIC_ASSERT(offsetof(StaffActivatedPlacement, scarabObjectSet) == 0x1E);
STATIC_ASSERT(offsetof(StaffActivatedPlacement, hitReactionType) == 0x1E);
STATIC_ASSERT(offsetof(StaffActivatedPlacement, scarabCount) == 0x1F);
STATIC_ASSERT(offsetof(StaffActivatedPlacement, debrisCount) == 0x1F);
STATIC_ASSERT(offsetof(StaffActivatedPlacement, timedEventSeconds) == 0x20);
STATIC_ASSERT(offsetof(StaffActivatedPlacement, pad21) == 0x21);
STATIC_ASSERT(offsetof(StaffActivatedPlacement, activeGameBit) == 0x22);
STATIC_ASSERT(offsetof(StaffActivatedPlacement, damagedGameBit) == 0x22);
STATIC_ASSERT(offsetof(StaffActivatedPlacement, siblingGameBit) == 0x22);
STATIC_ASSERT(offsetof(StaffActivatedPlacement, lockGameBit) == 0x24);
STATIC_ASSERT(offsetof(StaffActivatedPlacement, damageStateGameBit) == 0x24);
STATIC_ASSERT(offsetof(StaffActivatedPlacement, reactionCompleteGameBit) == 0x24);

STATIC_ASSERT(sizeof(StaffActivatedFlags) == 0x1);
STATIC_ASSERT(offsetof(StaffActivatedState, targetX) == 0x0);
STATIC_ASSERT(offsetof(StaffActivatedState, targetZ) == 0x4);
STATIC_ASSERT(offsetof(StaffActivatedState, pad08) == 0x8);
STATIC_ASSERT(offsetof(StaffActivatedState, liftVelocity) == 0xC);
STATIC_ASSERT(offsetof(StaffActivatedState, previousLiftHeight) == 0x10);
STATIC_ASSERT(offsetof(StaffActivatedState, liftHeight) == 0x14);
STATIC_ASSERT(offsetof(StaffActivatedState, peakLiftHeight) == 0x18);
STATIC_ASSERT(offsetof(StaffActivatedState, liftReset) == 0x1C);
STATIC_ASSERT(offsetof(StaffActivatedState, flags) == 0x1D);
STATIC_ASSERT(offsetof(StaffActivatedState, pad1E) == 0x1E);
STATIC_ASSERT(offsetof(StaffActivatedState, hitCooldown) == 0x20);
STATIC_ASSERT(sizeof(StaffActivatedState) == STAFF_ACTIVATED_STATE_SIZE);

void staffactivated_updateLiftHeight(GameObject* obj, StaffActivatedState* state);
void staffactivated_setGameBitMirror(GameObject* obj, u8 enabled);
int staffactivated_isGameBitMirrorSet(GameObject* obj);
void staffactivated_spawnMapEventDebris(GameObject* obj);
u32 staffactivated_getPullRateMode(GameObject* obj);
void staffactivated_calcInteractionTargetXZ(GameObject* obj, f32* outX, f32* outZ);
u32 staffactivated_getLiftHeight(GameObject* obj);
void staffactivated_setLiftHeight(GameObject* obj, int height);
u8 staffactivated_getMode(GameObject* obj);
int staffactivated_getExtraSize(void);
int staffactivated_getObjectTypeId(void);
void staffactivated_free(GameObject* obj);
void staffactivated_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
void staffactivated_update(GameObject* obj);
void staffactivated_init(GameObject* obj, StaffActivatedPlacement* placement);

extern ObjectDescriptor gStaffActivatedObjDescriptor;

#endif /* DLLS_OBJECTS_284_H_ */
