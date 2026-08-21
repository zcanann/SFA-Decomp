#ifndef DLLS_OBJECTS_245_SIDEKICKBAL_H_
#define DLLS_OBJECTS_245_SIDEKICKBAL_H_

#include "dolphin/mtx/vec.h"
#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "main/dll/curves_collision_state.h"

typedef enum SidekickBallMode {
    SIDEKICK_BALL_IDLE = 0,
    SIDEKICK_BALL_MOVING = 1,
    SIDEKICK_BALL_HELD = 2,
    SIDEKICK_BALL_THROWN = 3,
    SIDEKICK_BALL_FADING = 5
} SidekickBallMode;

typedef struct SidekickBallState {
    union {
        CurvesCollisionState pathControl; /* 0x000: gPathControlInterface state block */
        struct {
            u8 pathControlPrefix[0x68]; /* 0x000 */
            Vec collisionNormal;        /* 0x068 */
            u8 pad074[0x140];           /* 0x074 */
            f32 floorHeight;            /* 0x1B4 */
            u8 pad1B8[4];               /* 0x1B8 */
            f32 floorBaseY;             /* 0x1BC */
            u8 pad1C0[0x9B];            /* 0x1C0 */
            u8 hittableLatch;           /* 0x25B */
            u8 pad25C[5];               /* 0x25C */
            s8 hasCollisionNormal;      /* 0x261 */
            u8 pad262[6];               /* 0x262 */
        };
    };
    f32 primaryRadius;  /* 0x268 */
    f32 fadeTimer;      /* 0x26C */
    u8 pad270[4];       /* 0x270 */
    u8 ballMode;        /* 0x274: SidekickBallMode */
    u8 onPathPoint;     /* 0x275 */
    u8 pad276[0x22];    /* 0x276 */
    f32 unk298;         /* 0x298 */
    u8 pad29C[0x14];    /* 0x29C */
    f32 previousPosX;   /* 0x2B0 */
    f32 previousPosY;   /* 0x2B4 */
    f32 previousPosZ;   /* 0x2B8 */
    u8 pad2BC[4];       /* 0x2BC */
    f32 floorY;         /* 0x2C0 */
    f32 floorDepth;     /* 0x2C4 */
    u8 triggerArmed;    /* 0x2C8 */
    u8 triggerHit;      /* 0x2C9 */
    u8 sendHoldMessage; /* 0x2CA */
    u8 pad2CB;          /* 0x2CB */
} SidekickBallState;

STATIC_ASSERT(offsetof(SidekickBallState, pathControl) == 0x0);
STATIC_ASSERT(offsetof(SidekickBallState, pathControlPrefix) == 0x0);
STATIC_ASSERT(offsetof(SidekickBallState, collisionNormal) == 0x68);
STATIC_ASSERT(offsetof(SidekickBallState, pad074) == 0x74);
STATIC_ASSERT(offsetof(SidekickBallState, floorHeight) == 0x1B4);
STATIC_ASSERT(offsetof(SidekickBallState, pad1B8) == 0x1B8);
STATIC_ASSERT(offsetof(SidekickBallState, floorBaseY) == 0x1BC);
STATIC_ASSERT(offsetof(SidekickBallState, pad1C0) == 0x1C0);
STATIC_ASSERT(offsetof(SidekickBallState, hittableLatch) == 0x25B);
STATIC_ASSERT(offsetof(SidekickBallState, pad25C) == 0x25C);
STATIC_ASSERT(offsetof(SidekickBallState, hasCollisionNormal) == 0x261);
STATIC_ASSERT(offsetof(SidekickBallState, pad262) == 0x262);
STATIC_ASSERT(offsetof(SidekickBallState, primaryRadius) == 0x268);
STATIC_ASSERT(offsetof(SidekickBallState, fadeTimer) == 0x26C);
STATIC_ASSERT(offsetof(SidekickBallState, pad270) == 0x270);
STATIC_ASSERT(offsetof(SidekickBallState, ballMode) == 0x274);
STATIC_ASSERT(offsetof(SidekickBallState, onPathPoint) == 0x275);
STATIC_ASSERT(offsetof(SidekickBallState, pad276) == 0x276);
STATIC_ASSERT(offsetof(SidekickBallState, unk298) == 0x298);
STATIC_ASSERT(offsetof(SidekickBallState, pad29C) == 0x29C);
STATIC_ASSERT(offsetof(SidekickBallState, previousPosX) == 0x2B0);
STATIC_ASSERT(offsetof(SidekickBallState, previousPosY) == 0x2B4);
STATIC_ASSERT(offsetof(SidekickBallState, previousPosZ) == 0x2B8);
STATIC_ASSERT(offsetof(SidekickBallState, pad2BC) == 0x2BC);
STATIC_ASSERT(offsetof(SidekickBallState, floorY) == 0x2C0);
STATIC_ASSERT(offsetof(SidekickBallState, floorDepth) == 0x2C4);
STATIC_ASSERT(offsetof(SidekickBallState, triggerArmed) == 0x2C8);
STATIC_ASSERT(offsetof(SidekickBallState, triggerHit) == 0x2C9);
STATIC_ASSERT(offsetof(SidekickBallState, sendHoldMessage) == 0x2CA);
STATIC_ASSERT(offsetof(SidekickBallState, pad2CB) == 0x2CB);
STATIC_ASSERT(sizeof(SidekickBallState) == 0x2CC);

int sidekickBall_isIdle(GameObject* obj);
void sidekickBall_handlePlayerInteraction(GameObject* obj, SidekickBallState* state);
void sidekickBall_keepAlive(GameObject* obj);
int sidekickBall_isHeldOrMoving(GameObject* obj);
void sidekickBall_setIdle(GameObject* obj, GameObject* source);
void sidekickBall_launch(GameObject* obj, GameObject* source, f32 velocityX, f32 velocityY, f32 velocityZ);
int SidekickBall_getExtraSize(void);
void SidekickBall_free(int obj);
void SidekickBall_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible);
void SidekickBall_update(GameObject* obj);
u8 trickyBallMove(GameObject* obj);
void SidekickBall_init(GameObject* obj);

extern ObjectDescriptor gSidekickBallObjDescriptor;

#endif /* DLLS_OBJECTS_245_SIDEKICKBAL_H_ */
