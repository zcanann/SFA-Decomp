#ifndef MAIN_DLL_DLL_024D_BOSSDRAKOR_H_
#define MAIN_DLL_DLL_024D_BOSSDRAKOR_H_

#include "types.h"
#include "game/objects/object.h"
#include "main/byte_flags.h"
#include "main/dll/curve_walker.h"
#include "main/objprint_sound_api.h"
#include "main/model_light.h"
#include "main/objseq.h"
#include "global.h"
#include "game/objects/object_setup.h"

#define BOSSDRAKOR_OBJGROUP 0x45

typedef struct BossdrakorPlacement
{
    ObjPlacement base;
    u8 pad18[0x19 - 0x18];
    u8 curveAdvanceStep;
    s16 airMeterMax;
    s16 unk1C;
    s16 defeatedGameBit;
} BossdrakorPlacement;

typedef struct BossDrakorState
{
    f32 curveAdvanceStep;
    u8 pad04[8];
    int unk0C;
    f32 attackTimer;
    f32 attackTimerDuration;
    f32 jawAnimTimer;
    union {
        struct {
            f32 homePosX;
            f32 homePosY;
            f32 homePosZ;
        };
        Vec3f homePos;
    };
    RomCurveWalker curveWalker; /* 0x28: the rom-curve walker this boss follows */
    ObjSoundState soundState; /* 0x130 */
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
    ByteFlags flags198;
    u8 pad199[3];
    f32 hitSfxCooldown;
    f32 hurtSfxCooldown;
} BossDrakorState;

STATIC_ASSERT(offsetof(BossDrakorState, curveWalker) == 0x28);
STATIC_ASSERT(offsetof(BossDrakorState, soundState) == 0x130);
STATIC_ASSERT(sizeof(BossDrakorState) == 0x1a4);


extern f32 gBossDrakorMissileTargetScatterFactor;
extern f32 gBossDrakorMissileInitialSpeedFactor;
extern f32 gBossDrakorThornbushSpawnHealth;
extern f32 gBossDrakorThornbushBaseRadius;
extern s16 gBossDrakorMaxJawStepAngle;
extern s16 gBossDrakorJawAnglePerTick;

extern int gBossDrakorMoveStateTable[];
extern int gBossDrakorMoveSpeedTable[];
typedef struct BossDrakorTuning
{
    int turnMoveStates[5];
    f32 unk14[9];
    int unk38[9];
    f32 missileBaseSpeeds[3];
    f32 missileLeadFactors[3];
    int airMeterThresholds[3];
} BossDrakorTuning;

STATIC_ASSERT(sizeof(BossDrakorTuning) == 0x80);
STATIC_ASSERT(offsetof(BossDrakorTuning, unk14) == 0x14);
STATIC_ASSERT(offsetof(BossDrakorTuning, unk38) == 0x38);
STATIC_ASSERT(offsetof(BossDrakorTuning, missileBaseSpeeds) == 0x5c);
STATIC_ASSERT(offsetof(BossDrakorTuning, missileLeadFactors) == 0x68);
STATIC_ASSERT(offsetof(BossDrakorTuning, airMeterThresholds) == 0x74);

extern BossDrakorTuning gBossDrakorTurnMoveStates;

void bossdrakor_release(void);
void bossdrakor_initialise(void);
int bossdrakor_getExtraSize(void);
void bossdrakor_update(GameObject* obj);
void bossdrakor_free(GameObject* obj);
void bossdrakor_hitDetect(GameObject* obj);
int bossdrakor_seqFn(GameObject* obj, int unused, ObjSeqState* animUpdate);
void bossdrakor_handleActionEvent(GameObject* obj, BossDrakorState* state, int action);
void bossdrakor_updateHeadTracking(GameObject* obj, BossDrakorState* drakorState);
int bossdrakor_chooseNextMove(GameObject* obj, f32* speedOut);
void bossdrakor_spawnAttackObjects(GameObject* obj, BossDrakorState* state, int action);
void bossdrakor_init(GameObject* obj, BossdrakorPlacement* init);
void bossdrakor_render(GameObject* p1, int p2, int p3, int p4, int p5, s8 vis);

#endif
