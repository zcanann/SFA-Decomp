#ifndef DLLS_OBJECTS_262_H_
#define DLLS_OBJECTS_262_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

#define SCARAB_PLACEMENT_SIZE 0x24
#define SCARAB_STATE_SIZE     0x34

#define SCARAB_OBJECT_GREEN     0x3D3 /* GreenScarab */
#define SCARAB_OBJECT_RED       0x3D4 /* RedScarab */
#define SCARAB_OBJECT_GOLD      0x3D5 /* GoldScarab */
#define SCARAB_OBJECT_RAIN      0x3D6 /* RainScarab */
#define SCARAB_OBJECT_BLUE_BEAN 0x3DF /* Blue_bean */

typedef enum ScarabBehaviorState {
    SCARAB_STATE_TUMBLING = 0,
    SCARAB_STATE_SCURRYING = 1,
    SCARAB_STATE_GOLD_CLIMB = 2,
} ScarabBehaviorState;

typedef enum ScarabPickupFlags {
    SCARAB_PICKUP_PENDING = 1 << 0,
} ScarabPickupFlags;

typedef enum ScarabMoneyKind {
    SCARAB_MONEY_GREEN = 0,
    SCARAB_MONEY_RED = 1,
    SCARAB_MONEY_GOLD = 2,
    SCARAB_MONEY_RAIN = 3,
} ScarabMoneyKind;

/* Transient ground selection and collision response used by Scarab_update. */
typedef struct ScarabContactState {
    int bestGroundHitIndex;
    int collisionDetected;
} ScarabContactState;

/* Basket and crate spawners allocate the complete 0x24-byte placement record. */
typedef struct ScarabPlacement {
    ObjPlacement base; /* 0x00 */
    s8 yawByte;        /* 0x18 */
    u8 pad19;          /* 0x19 */
    s16 activeTimer;   /* 0x1A: active lifetime in frames */
    u8 pad1C[8];       /* 0x1C */
} ScarabPlacement;

/* Scarab_getExtraSize allocates the complete 0x34-byte state block. */
typedef struct ScarabState {
    f32 speedX;             /* 0x00: scurry speed */
    f32 speedZ;             /* 0x04: scurry speed */
    f32 goldClimbTimer;     /* 0x08 */
    f32 initialY;           /* 0x0C: fallback ground height */
    s16 destructDelayTimer; /* 0x10 */
    u8 pad12[2];            /* 0x12 */
    s16 lifetime;           /* 0x14: zero begins despawn */
    s16 rollSpeed;          /* 0x16 */
    s16 scurryInitialYaw;   /* 0x18 */
    s16 stunTimer;          /* 0x1A */
    s16 goldClimbDuration;  /* 0x1C */
    s16 collectSfxId;       /* 0x1E */
    s16 particleId;         /* 0x20 */
    s16 burstModel;         /* 0x22 */
    s8 behaviorState;       /* 0x24: ScarabBehaviorState */
    u8 pad25[2];            /* 0x25 */
    u8 moneyKind;           /* 0x27: ScarabMoneyKind */
    u8 pickupFlags;         /* 0x28: ScarabPickupFlags; waiting on pickup reply */
    u8 pad29[3];            /* 0x29 */
    s16 messageParamA;      /* 0x2C */
    s16 messageParamB;      /* 0x2E */
    f32 messageParamC;      /* 0x30 */
} ScarabState;

STATIC_ASSERT(offsetof(ScarabPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(ScarabPlacement, yawByte) == 0x18);
STATIC_ASSERT(offsetof(ScarabPlacement, pad19) == 0x19);
STATIC_ASSERT(offsetof(ScarabPlacement, activeTimer) == 0x1A);
STATIC_ASSERT(offsetof(ScarabPlacement, pad1C) == 0x1C);
STATIC_ASSERT(sizeof(ScarabPlacement) == SCARAB_PLACEMENT_SIZE);

STATIC_ASSERT(offsetof(ScarabState, speedX) == 0x0);
STATIC_ASSERT(offsetof(ScarabState, speedZ) == 0x4);
STATIC_ASSERT(offsetof(ScarabState, goldClimbTimer) == 0x8);
STATIC_ASSERT(offsetof(ScarabState, initialY) == 0xC);
STATIC_ASSERT(offsetof(ScarabState, destructDelayTimer) == 0x10);
STATIC_ASSERT(offsetof(ScarabState, pad12) == 0x12);
STATIC_ASSERT(offsetof(ScarabState, lifetime) == 0x14);
STATIC_ASSERT(offsetof(ScarabState, rollSpeed) == 0x16);
STATIC_ASSERT(offsetof(ScarabState, scurryInitialYaw) == 0x18);
STATIC_ASSERT(offsetof(ScarabState, stunTimer) == 0x1A);
STATIC_ASSERT(offsetof(ScarabState, goldClimbDuration) == 0x1C);
STATIC_ASSERT(offsetof(ScarabState, collectSfxId) == 0x1E);
STATIC_ASSERT(offsetof(ScarabState, particleId) == 0x20);
STATIC_ASSERT(offsetof(ScarabState, burstModel) == 0x22);
STATIC_ASSERT(offsetof(ScarabState, behaviorState) == 0x24);
STATIC_ASSERT(offsetof(ScarabState, pad25) == 0x25);
STATIC_ASSERT(offsetof(ScarabState, moneyKind) == 0x27);
STATIC_ASSERT(offsetof(ScarabState, pickupFlags) == 0x28);
STATIC_ASSERT(offsetof(ScarabState, pad29) == 0x29);
STATIC_ASSERT(offsetof(ScarabState, messageParamA) == 0x2C);
STATIC_ASSERT(offsetof(ScarabState, messageParamB) == 0x2E);
STATIC_ASSERT(offsetof(ScarabState, messageParamC) == 0x30);
STATIC_ASSERT(sizeof(ScarabState) == SCARAB_STATE_SIZE);

int Scarab_getExtraSize(void);
void Scarab_free(GameObject* obj);
void Scarab_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
void Scarab_update(GameObject* obj);
void Scarab_init(GameObject* obj, const ScarabPlacement* placement);

extern ObjectDescriptor gScarabObjDescriptor;

#endif /* DLLS_OBJECTS_262_H_ */
