#ifndef MAIN_DLL_DLL_024D_BOSSDRAKOR_H_
#define MAIN_DLL_DLL_024D_BOSSDRAKOR_H_

#include "types.h"
#include "main/game_object.h"
#include "main/model_light.h"
#include "main/objanim_update.h"
#include "global.h"

typedef struct
{
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 b10 : 1;
    u8 b08 : 1;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} DrakorFlags;

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
    ModelLightStruct* lightObj; /* 0x160 */
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

extern f32 lbl_803E6510;
extern f32 lbl_803E6514;
extern f32 lbl_803E6518;
extern f32 lbl_803E651C;
extern f32 lbl_803E6520;
extern f32 gBossDrakorDegToAngle;
extern f32 lbl_803E6534;
extern f32 lbl_803E6538;
extern f32 lbl_803E653C;
extern f32 lbl_803E6540;
extern f32 lbl_803E6544;
extern f32 lbl_803E6548;
extern f32 lbl_803E654C;
extern f32 lbl_803E6550;
extern f32 lbl_803E6554;
extern f32 lbl_803E6558;
extern f32 lbl_803E655C;
extern f32 lbl_803E6560;
extern f32 lbl_803E6564;
extern f32 lbl_803E6568;
extern f32 lbl_803E656C;
extern f32 lbl_803E6570;
extern f32 lbl_803E6574;
extern f32 lbl_803E6578;
extern f32 lbl_803E657C;

extern f32 lbl_803DC188;
extern f32 lbl_803DC18C;
extern f32 lbl_803DC190;
extern f32 lbl_803DC194;
extern s16 lbl_803DC198;
extern s16 lbl_803DC19A;

extern int gBossDrakorMoveStateTable[];
extern int gBossDrakorMoveSpeedTable[];
extern int gBossDrakorTurnMoveStates[];

void bossdrakor_release(void);
void bossdrakor_initialise(void);
int bossdrakor_getExtraSize(void);
void bossdrakor_update(int obj);
void bossdrakor_free(GameObject* obj);
void bossdrakor_hitDetect(GameObject* obj);
int bossdrakor_seqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void bossdrakor_handleActionEvent(int obj, int state, int action);
void bossdrakor_updateHeadTracking(GameObject* obj, int state);
int bossdrakor_chooseNextMove(GameObject* obj, f32* speedOut);
void bossdrakor_spawnAttackObjects(GameObject* obj, int state, int action);
void bossdrakor_init(GameObject* obj, BossdrakorPlacement* init);
void bossdrakor_render(int p1, int p2, int p3, int p4, int p5, s8 vis);

#endif
