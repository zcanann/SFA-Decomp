#ifndef DLLS_OBJECTS_255_H_
#define DLLS_OBJECTS_255_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "main/dll/curves_collision_state.h"
#include "dlls/objects/237.h"

#define MAGICGEM_STATE_SIZE     0x288

#define MAGICGEM_DEF_GREEN  0x2C4
#define MAGICGEM_DEF_RED    0x2CD
#define MAGICGEM_DEF_YELLOW 0x2CE
#define MAGICGEM_DEF_BLUE   0x2CF

#define MAGICGEM_FLAG_BURST1        0x01 /* First timed particle-burst phase. */
#define MAGICGEM_FLAG_SETTLED       0x02 /* At rest after repeated bounces. */
#define MAGICGEM_FLAG_BURST2        0x04 /* Second timed particle-burst phase. */
#define MAGICGEM_FLAG_COLLECTED     0x08 /* Collected/despawning. */
#define MAGICGEM_FLAG_AMBIENT_FX    0x10 /* Proximity effects are active. */
#define MAGICGEM_FLAG_CLAIMED       0x20 /* Pickup message and game-bit claim sent. */
#define MAGICGEM_FLAG_COLLECT_LATCH 0x40 /* Collection path has been taken. */

#define MAGICGEM_FLAG_MOTION_MASK (MAGICGEM_FLAG_BURST1 | MAGICGEM_FLAG_SETTLED)
#define MAGICGEM_FLAG_BURST_MASK  (MAGICGEM_FLAG_BURST1 | MAGICGEM_FLAG_BURST2)

/* MagicDust_getExtraSize allocates the complete 0x288-byte state block. */
typedef struct MagicGemState {
    CurvesCollisionState path; /* 0x000 */
    f32 collectRadius;       /* 0x268: added to the base pickup radius */
    f32 burstTimer;          /* 0x26C: time until the next burst phase */
    u16 burstEffectId;       /* 0x270 */
    u16 ambientEffectId;     /* 0x272 */
    s16 sfxId;               /* 0x274: collection sound */
    s16 unk276;              /* 0x276 */
    s16 ambientTimer;        /* 0x278 */
    u8 flags;                /* 0x27A: MAGICGEM_FLAG_* */
    u8 bounceCount;          /* 0x27B */
    u8 mode;                 /* 0x27C: particle-colour row */
    u8 pad27D[3];            /* 0x27D */
    s16 pickupMsgArg;        /* 0x280 */
    u8 pad282[6];            /* 0x282 */
} MagicGemState;

STATIC_ASSERT(offsetof(MagicGemState, collectRadius) == 0x268);
STATIC_ASSERT(offsetof(MagicGemState, burstTimer) == 0x26C);
STATIC_ASSERT(offsetof(MagicGemState, burstEffectId) == 0x270);
STATIC_ASSERT(offsetof(MagicGemState, ambientEffectId) == 0x272);
STATIC_ASSERT(offsetof(MagicGemState, sfxId) == 0x274);
STATIC_ASSERT(offsetof(MagicGemState, unk276) == 0x276);
STATIC_ASSERT(offsetof(MagicGemState, ambientTimer) == 0x278);
STATIC_ASSERT(offsetof(MagicGemState, flags) == 0x27A);
STATIC_ASSERT(offsetof(MagicGemState, bounceCount) == 0x27B);
STATIC_ASSERT(offsetof(MagicGemState, mode) == 0x27C);
STATIC_ASSERT(offsetof(MagicGemState, pad27D) == 0x27D);
STATIC_ASSERT(offsetof(MagicGemState, pickupMsgArg) == 0x280);
STATIC_ASSERT(offsetof(MagicGemState, pad282) == 0x282);
STATIC_ASSERT(sizeof(MagicGemState) == MAGICGEM_STATE_SIZE);

int MagicDust_getExtraSize(void);
void MagicDust_free(GameObject* obj);
void MagicDust_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 unusedVisible);
void MagicDust_update(GameObject* obj);
void MagicDust_init(GameObject* obj, CollectibleSetup* placement);

extern ObjectDescriptor gMagicGemObjDescriptor;

#endif /* DLLS_OBJECTS_255_H_ */
