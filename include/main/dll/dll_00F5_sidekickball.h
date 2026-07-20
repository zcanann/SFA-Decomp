#ifndef MAIN_DLL_DLL_00F5_SIDEKICKBALL_H_
#define MAIN_DLL_DLL_00F5_SIDEKICKBALL_H_

#include "ghidra_import.h"
#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

typedef struct SidekickBallState {
    u8 unk000[0x68];
    f32 collisionNormal[3];
    u8 pad074[0x1B4 - 0x74];
    f32 floorHeight;
    u8 pad1B8[0x1BC - 0x1B8];
    f32 floorBaseY;
    u8 pad1C0[0x25B - 0x1C0];
    u8 hittableLatch;
    u8 pad25C[0x261 - 0x25C];
    s8 hasCollisionNormal;
    u8 pad262[0x26C - 0x262];
    f32 fadeTimer;
    u8 pad270[4];
    u8 ballMode;
    u8 onPathPoint;
    u8 pad276[0x298 - 0x276];
    f32 unk298;
    u8 pad29C[0x2B0 - 0x29C];
    f32 previousPosX;
    f32 previousPosY;
    f32 previousPosZ;
    u8 pad2BC[0x2C0 - 0x2BC];
    f32 floorY;
    f32 floorDepth;
    u8 triggerArmed;
    u8 triggerHit;
    u8 sendHoldMessage[2];
} SidekickBallState;

STATIC_ASSERT(offsetof(SidekickBallState, collisionNormal) == 0x68);
STATIC_ASSERT(offsetof(SidekickBallState, floorHeight) == 0x1B4);
STATIC_ASSERT(offsetof(SidekickBallState, floorBaseY) == 0x1BC);
STATIC_ASSERT(offsetof(SidekickBallState, hittableLatch) == 0x25B);
STATIC_ASSERT(offsetof(SidekickBallState, hasCollisionNormal) == 0x261);
STATIC_ASSERT(offsetof(SidekickBallState, fadeTimer) == 0x26C);
STATIC_ASSERT(offsetof(SidekickBallState, ballMode) == 0x274);
STATIC_ASSERT(offsetof(SidekickBallState, onPathPoint) == 0x275);
STATIC_ASSERT(offsetof(SidekickBallState, previousPosX) == 0x2B0);
STATIC_ASSERT(offsetof(SidekickBallState, floorY) == 0x2C0);
STATIC_ASSERT(offsetof(SidekickBallState, floorDepth) == 0x2C4);
STATIC_ASSERT(offsetof(SidekickBallState, triggerArmed) == 0x2C8);
STATIC_ASSERT(offsetof(SidekickBallState, triggerHit) == 0x2C9);
STATIC_ASSERT(offsetof(SidekickBallState, sendHoldMessage) == 0x2CA);
STATIC_ASSERT(sizeof(SidekickBallState) == 0x2CC);

extern ObjectDescriptor gSidekickBallObjDescriptor;

int sidekickBall_isIdle(GameObject* obj);
void sidekickBall_handlePlayerInteraction(GameObject* obj, SidekickBallState* state);
void sidekickBall_keepAlive(GameObject* obj);
int sidekickBall_isHeldOrMoving(GameObject* obj);
void sidekickBall_setIdle(GameObject* obj, GameObject* source);
void sidekickBall_launch(GameObject* obj, GameObject* source, f32 velocityX, f32 velocityY, f32 velocityZ);
int SidekickBall_getExtraSize(void);
void SidekickBall_free(int obj);
void SidekickBall_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void SidekickBall_update(GameObject* obj);
void SidekickBall_init(GameObject* obj);
u8 trickyBallMove(GameObject* obj);
void FUN_80179b34(double param_1,double param_2,double param_3,u64 param_4,u64 param_5
                 ,u64 param_6,u64 param_7,u64 param_8,u16 *param_9,
                 u32 param_10,u32 param_11,u32 param_12,u32 param_13,
                 u32 param_14,u32 param_15,u32 param_16);

#endif /* MAIN_DLL_DLL_00F5_SIDEKICKBALL_H_ */
