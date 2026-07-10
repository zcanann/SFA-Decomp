#ifndef MAIN_DLL_DLL_024D_BOSSDRAKOR_H_
#define MAIN_DLL_DLL_024D_BOSSDRAKOR_H_

#include "types.h"
#include "main/game_object.h"
#include "global.h"

typedef struct BossdrakorPlacement
{
    u8 pad0[0x19 - 0x0];
    u8 curveStartIndex;
    s16 airMeterMax;
    s16 unk1C;
    s16 defeatedGameBit;
} BossdrakorPlacement;

typedef struct BossDrakorState
{
    f32 curveIndex;
    u8 pad04[8];
    int unk0C;
    f32 attackTimer;
    f32 attackTimerDuration;
    f32 jawAnimAngle;
    f32 homePosX;
    f32 homePosY;
    f32 homePosZ;
    u8 pad28[0x68];
    f32 savedPosX;
    f32 savedPosY;
    f32 savedPosZ;
    u8 pad9C[0xc4];
    int lightObj; /* 0x160 */
    f32 moveSpeed;
    int moveState; /* 0x168 */
    int unk16C;
    int airMeterHandle;
    int attackType;
    f32 shakeAmount;
    f32 shakeVel;
    f32 shakeScaleZ;
    f32 missileBaseSpeed;  /* 0x184: base missile speed (constant term of spd); also scales missile lateral vel */
    f32 missileLeadFactor; /* 0x188: coefficient on dot(playerVel, dir) added to base speed (target-lead) */
    f32 textTimer;
    u8 repeatCount;
    u8 pad191[3];
    int curveFollowState;
    u8 pad198[4];
    f32 hitSfxCooldown;
    f32 hurtSfxCooldown;
} BossDrakorState;

STATIC_ASSERT(sizeof(BossDrakorState) == 0x1a4);

void bossdrakor_release(void);
void bossdrakor_initialise(void);
int bossdrakor_getExtraSize(void);
void bossdrakor_update(int obj);
void bossdrakor_free(GameObject* obj);
void bossdrakor_hitDetect(GameObject* obj);
void bossdrakor_init(GameObject* obj, BossdrakorPlacement* init);
void bossdrakor_render(int p1, int p2, int p3, int p4, int p5, s8 vis);

#endif
