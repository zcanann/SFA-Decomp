/*
 * sandwormBoss.c - 10-DLL container (DLL 0x14A CFPowerBase .. 0x157
 * SpiritDoorSpirit), TU [8019D578-801A0B14). DLLs 0x148 and 0x149 are
 * defined in dll_0148_cfguardian.c and dll_0149_cfwindlift.c; their
 * definitions here are collapsed to forward prototypes.
 */
#include "main/dll/cfguardian_state.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/vecmath.h"
#include "main/dll/wormspitbyte_struct.h"
#include "main/dll/cfprisonunclestate_struct.h"
#include "main/dll/babycloudrunnerflags_struct.h"
#include "main/dll/gcrobotlightbeastate_struct.h"
#include "main/dll/cfprisonguardstate_struct.h"
#include "main/dll/cfpowerbasestate_struct.h"
#include "main/dll/cfmaincrystalstate_types.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/frame_timing.h"
#include "main/obj_placement.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objseq.h"
#include "main/audio/sfx.h"
#include "main/gameloop_api.h"
#include "main/maketex.h"
#include "main/objprint.h"
#include "main/dll/babycloudrunnerstate_struct.h"

/* Per-object extra state for the baby CloudRunner
 * (babycloudrunner_getExtraSize == 0x248). */

STATIC_ASSERT(sizeof(BabyCloudRunnerState) == 0x248);

/* Placement record for the baby cloud runner (ObjPlacement head + tuning). */
typedef struct BabyCloudRunnerPlacement
{
    ObjPlacement base; /* 0x00: posX/posY/posZ at 0x08/0x0c/0x10 = roost point */
    s16 outerRadius;   /* 0x18: outer trigger radius */
    s16 innerRadius;   /* 0x1a: inner trigger radius (halved for proximity tests) */
    u8 behaviourState; /* 0x1c: initial BabyCloudRunnerState.behaviourState */
    u8 initialYaw;     /* 0x1d: << 8 -> rotX */
    s16 enableBit;     /* 0x1e: gamebit set on capture */
    u8 pad20[2];
    s16 runnerGameBit; /* 0x22: despawn gamebit; -0x2fc -> runnerIndex */
} BabyCloudRunnerPlacement;

STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, outerRadius) == 0x18);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, innerRadius) == 0x1a);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, behaviourState) == 0x1c);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, initialYaw) == 0x1d);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, enableBit) == 0x1e);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, runnerGameBit) == 0x22);

/* Per-object extra state for the CloudRunner guardian
 * (cfguardian_getExtraSize == 0xa9c). */
STATIC_ASSERT(sizeof(CfGuardianState) == 0xa9c);

/* Per-object extra state for the CloudRunner main crystal
 * (CFMainCrystal_getExtraSize == 0x160). */

STATIC_ASSERT(sizeof(CfMainCrystalState) == 0x160);

/* Per-object extra state for the CloudRunner power base
 * (CFPowerBase_getExtraSize == 0x6). */

STATIC_ASSERT(sizeof(CfPowerBaseState) == 0x6);

/* Per-object extra state for the CloudRunner prison guard
 * (CFPrisonGuard_getExtraSize == 0x3c). */

STATIC_ASSERT(sizeof(CfPrisonGuardState) == 0x3c);

/* Per-object extra state for the CloudRunner prison uncle
 * (cfprisonuncle_getExtraSize == 0xa8). */

STATIC_ASSERT(sizeof(CfPrisonUncleState) == 0xa8);

/* Per-object extra state for the robot light beacon
 * (gcrobotlightbea_getExtraSize == 0xc). */

STATIC_ASSERT(sizeof(GcRobotLightBeaState) == 0xc);

typedef struct
{
    s16 a, b, c;
    u8 pad[6];
    f32 x, y, z;
} RunnerTarget;

#define BABYCLOUDRUNNER_OBJFLAG_PARENT_SLACK 0x1000
#define BABYCLOUDRUNNER_OBJGROUP             3
#define BABYCLOUDRUNNER_OBJGROUP_SECONDARY   0x20
#define BABYCLOUDRUNNER_AIRMETER_BGTEXTURE   0x5d1 /* HUD air-meter background texture id */

extern f32 lbl_803E4228;
extern f32 lbl_803E422C;
extern f32 lbl_803E4244;
extern f32 lbl_803E4258;
extern u8 gBabyCloudRunnerMutterSfxTable;
extern u8 gBabyCloudRunnerMutterSfxTableSpecial;
extern f32 lbl_803E4218;
extern f32 lbl_803E423C;
extern f32 lbl_803E4240;
extern f32 lbl_803E4230;
extern f32 lbl_803E4234;
extern f32 lbl_803DBE4C;
extern f32 lbl_803E4248;
extern int gBabyCloudRunnerAirMeterValues[];
extern f32 gBabyCloudRunnerTargetNearDist;
extern f32 gBabyCloudRunnerPlayerFarDist;
extern f32 lbl_803DBE40;
extern f32 lbl_803DBE44;
extern f32 lbl_803DBE48;
extern f32 lbl_803E4238;
extern f32 lbl_803E424C;
extern f32 lbl_803E4250;
extern f32 lbl_803E4254;

extern u32 ObjHits_DisableObject();
extern u32 ObjHits_EnableObject();
extern int ObjGroup_FindNearestObject();
extern u64 ObjGroup_RemoveObject();
extern u32 ObjGroup_AddObject();
extern void ObjMsg_AllocQueue(void* obj, int capacity);
extern int Obj_GetYawDeltaToObject();
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void storeZeroToFloatParam(void* p);
extern u32 mainGetBit(int eventId);
extern int Obj_RemoveFromUpdateList(int* obj);
extern void fn_8003ADC4(GameObject* a, int* b, void* c, int d, int e, int f);
extern f32 s16toFloat(int a, int b);
extern void objAudioFn_800393f8(int obj, void* p, int a, int b, int c, int d);
extern void* getTrickyObject(void);
extern void fn_8014C66C(int* a, void* b);
extern int dll_2E_func0D(int* obj, void* p, f32 f, int c, f32* a, f32* b);
int CFPrisonGuard_getExtraSize(void);

#pragma scheduling off
#pragma peephole off
void babycloudrunner_init(int* obj, u8* defBytes)
{
    BabyCloudRunnerState* sub;
    BabyCloudRunnerPlacement* def = (BabyCloudRunnerPlacement*)defBytes;

    ObjHits_EnableObject(obj);
    ObjMsg_AllocQueue(obj, 4);
    ((GameObject*)obj)->animEventCallback = babycloudrunner_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)(def->initialYaw << 8);
    ObjGroup_AddObject(obj, BABYCLOUDRUNNER_OBJGROUP);
    sub = ((GameObject*)obj)->extra;
    sub->unkB0 = 0;
    sub->unkB4 = 0;
    sub->unkB8 = 0;
    sub->unkBC = 0;
    sub->turnLatch = 0;
    sub->behaviourState = def->behaviourState;
    sub->unkCC = 0;
    storeZeroToFloatParam(sub);
    sub->linkedObj = 0;
    sub->roostYaw = ((GameObject*)obj)->anim.rotX;
    sub->flags22C = 0;
    sub->animSpeed = lbl_803E422C;
    sub->runnerState = 0;
    if (mainGetBit(def->runnerGameBit) != 0)
    {
        ObjHits_DisableObject(obj);
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        sub->flags22C = (u8)(sub->flags22C & ~1);
        Obj_RemoveFromUpdateList(obj);
        ObjGroup_RemoveObject(obj, BABYCLOUDRUNNER_OBJGROUP);
    }
    else
    {
        sub->runnerIndex = def->runnerGameBit - 0x2fc;
        if (((GameObject*)obj)->anim.seqId == 0x788)
        {
            sub->runnerIndex = -1;
            sub->curveSpeed = lbl_803E4244;
            sub->mutterSfxTable = &gBabyCloudRunnerMutterSfxTableSpecial;
        }
        else
        {
            if (sub->runnerIndex < 0 || sub->runnerIndex > 4)
            {
                sub->runnerState = 3;
            }
            sub->curveSpeed = lbl_803E4258;
            sub->mutterSfxTable = &gBabyCloudRunnerMutterSfxTable;
            ObjGroup_AddObject(obj, BABYCLOUDRUNNER_OBJGROUP_SECONDARY);
        }
        ((BabyCloudrunnerFlags*)&sub->spitFlags)->resetLatch = 0;
    }
}

#pragma scheduling on
void babycloudrunner_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 isVisible;

    isVisible = visible;
    if (isVisible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E4228);
    }
    return;
}

#pragma peephole on

/* Turn toward the target by a fraction of the yaw delta; when roughly aligned
 * play/advance the idle move, otherwise start or speed-scale the turn move by
 * the delta. */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void sandworm_turnTowardTargetAnim(int obj, int target, BabyCloudRunnerState* sub, int playMove)
{
    int shifted;
    register int sum;
    fn_8003ADC4((GameObject*)obj, (int*)target, sub->lookBlock, 0x28, 0, 3);
    shifted = Obj_GetYawDeltaToObject(obj, target, 0);
    sum = ((GameObject*)obj)->anim.rotX + (shifted >>= 3);
    asm { sth sum, 0(r28) }
    if (playMove == 0)
        return;
    if ((s16)shifted > -200 && (s16)shifted < 200)
    {
        if (sub->turnLatch != 0)
        {
            sub->turnLatch = 0;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E4218, 0);
        }
        else
        {
            ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E423C, timeDelta, 0);
        }
    }
    else
    {
        if (sub->turnLatch == 0)
        {
            sub->turnLatch = 1;
            ObjAnim_SetCurrentMove(obj, 9, lbl_803E4218, 0);
        }
        else
        {
            int t;
            if ((int)(s16)shifted > 0)
            {
                t = (s16)shifted >> 2;
            }
            else
            {
                t = -(s16)shifted >> 2;
            }
            ObjAnim_AdvanceCurrentMove((int)obj, (f32)(s16)t / lbl_803E4240, timeDelta, 0);
        }
    }
}
#pragma opt_common_subs reset
#pragma peephole on
#pragma dont_inline reset

/* When the player gets within the trigger radius and the runner is in state 3,
 * fire its burst (notify, bump the counter, set the gamebit); otherwise just
 * play the idle audio cue. */
#pragma peephole off
int babycloudrunner_tryCapture(void* p)
{
    int* obj;
    int flag;
    BabyCloudRunnerPlacement* r;
    BabyCloudRunnerState* sub;
    BabyCloudRunnerPlacement* q;
    void* player;
    obj = p;
    sub = ((GameObject*)obj)->extra;
    q = *(BabyCloudRunnerPlacement**)&((GameObject*)obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    r = *(BabyCloudRunnerPlacement**)&((GameObject*)obj)->anim.placementData;
    flag = 0;
    if (Vec_distance(&((GameObject*)player)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX) <
        (f32)(s16)r->innerRadius)
    {
        if (sub->runnerState == 3)
        {
            if ((((GameObject*)obj)->objectFlags & BABYCLOUDRUNNER_OBJFLAG_PARENT_SLACK) == 0)
            {
                flag = 1;
            }
        }
    }
    if (flag != 0)
    {
        s16toFloat((int)sub, 0x3c);
        ((GameObject*)obj)->unkF4 = 1;
        ((GameObject*)obj)->anim.rotX = sub->roostYaw;
        (*gObjectTriggerInterface)->runSequence(4, obj, -1);
        sub->unk00 = lbl_803E4244;
        gameBitIncrement(0x901);
        sub->behaviourState = 0xc;
        mainSetBits(q->enableBit, 1);
        ((GameObject*)obj)->unkF4 = 0;
        return 1;
    }
    objAudioFn_800393f8((int)obj, sub->audioBlock, 0x296, 0x1000, -1, 1);
    Sfx_PlayFromObject((int)obj, SFXTRIG_wp_ice_freeze);
    return 0;
}
#pragma peephole reset

#pragma scheduling on
void babycloudrunner_hitDetect(void)
{
}

void babycloudrunner_release(void)
{
}

void babycloudrunner_initialise(void)
{
}

int babycloudrunner_getExtraSize(void)
{
    return 0x248;
}

int babycloudrunner_getObjectTypeId(void)
{
    return 0;
}

#pragma scheduling off
#pragma peephole off
int babycloudrunner_setScale(int* obj)
{
    BabyCloudRunnerState* state = ((GameObject*)obj)->extra;
    return !(state->flags22C & 1);
}

void babycloudrunner_free(int* obj)
{
    ObjGroup_RemoveObject(obj, BABYCLOUDRUNNER_OBJGROUP_SECONDARY);
    ObjGroup_RemoveObject(obj, BABYCLOUDRUNNER_OBJGROUP);
}

/* Pick the burrow/surface move from the vertical speed, clamp the playback
 * rate, latch the spit SFX while surfacing fast, and advance the current
 * move. */
#pragma dont_inline on
#pragma opt_common_subs off
int fn_8019E3F4(int* obj)
{
    f32 speed;
    BabyCloudRunnerState* sub = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.currentMove != 5 && ((GameObject*)obj)->anim.currentMove != 0xd)
    {
        ObjAnim_SetCurrentMove((int)obj, 0xd, ((GameObject*)obj)->anim.currentMoveProgress, 0);
    }
    if (((GameObject*)obj)->anim.currentMove == 5 && ((GameObject*)obj)->anim.velocityY > lbl_803E422C)
    {
        ObjAnim_SetCurrentMove((int)obj, 0xd, ((GameObject*)obj)->anim.currentMoveProgress, 0);
    }
    if (((GameObject*)obj)->anim.currentMove == 0xd && ((GameObject*)obj)->anim.velocityY < lbl_803E4218)
    {
        ObjAnim_SetCurrentMove((int)obj, 5, ((GameObject*)obj)->anim.currentMoveProgress, 0);
    }
    speed = ((GameObject*)obj)->anim.velocityY * lbl_803DBE4C + lbl_803E4230;
    speed *= lbl_803E4234;
    if (speed < lbl_803E4218)
    {
        speed = lbl_803E4218;
    }
    if (speed > lbl_803E4234)
    {
        speed = lbl_803E4234;
    }
    if (((GameObject*)obj)->anim.currentMove == 0xd)
    {
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E4234)
        {
            if (!((WormSpitByte*)&sub->spitFlags)->spitLatch)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_mn_heart1_c_334);
                ((WormSpitByte*)&sub->spitFlags)->spitLatch = 1;
            }
        }
        else
        {
            ((WormSpitByte*)&sub->spitFlags)->spitLatch = 0;
        }
    }
    ObjAnim_AdvanceCurrentMove((int)obj, speed, timeDelta, 0);
    return 1;
}
#pragma opt_common_subs reset
#pragma dont_inline reset

/* Range-check the runner against the player and its trigger radii, chirp for
 * queued cues, then steer toward the player (or Tricky) per the current
 * behaviour state. */
int babycloudrunner_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    BabyCloudRunnerPlacement* def = *(BabyCloudRunnerPlacement**)&((GameObject*)obj)->anim.placementData;
    s8 inRange;
    s8 i;
    int yaw;
    u8* animUpdateBytes = (u8*)animUpdate;
    f32 dx;
    f32 dz;
    f32 distSq;
    BabyCloudRunnerState* sub = ((GameObject*)obj)->extra;
    char* player;
    if (((GameObject*)obj)->seqIndex == 4)
    {
        return 0;
    }
    animUpdate->sequenceEventActive = 0;
    player = (char*)Obj_GetPlayerObject();
    dx = ((GameObject*)player)->anim.localPosX - def->base.posX;
    dz = ((GameObject*)player)->anim.localPosZ - def->base.posZ;
    distSq = dx * dx + dz * dz;
    if (distSq < (f32)((def->innerRadius / 2) * (def->innerRadius / 2)))
    {
        inRange = 1;
    }
    else
    {
        inRange = 0;
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
    {
        BabyCloudRunnerState* sub2 = ((GameObject*)obj)->extra;
        char* pp = (char*)Obj_GetPlayerObject();
        BabyCloudRunnerPlacement* def2 = *(BabyCloudRunnerPlacement**)&((GameObject*)obj)->anim.placementData;
        int found = 0;
        if (Vec_distance((f32*)(pp + 0x18), (f32*)((char*)((int)obj + 0x18))) < (f32)def2->innerRadius &&
            sub2->runnerState == 3 &&
            (((GameObject*)obj)->objectFlags & BABYCLOUDRUNNER_OBJFLAG_PARENT_SLACK) == 0)
        {
            found = 1;
        }
        if (found != 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
    }
    if (inRange == 0 && sub->runnerState == 2)
    {
        f32 radius = (f32)def->outerRadius;
        if ((void*)ObjGroup_FindNearestObject(BABYCLOUDRUNNER_OBJGROUP, obj, &radius) != NULL)
        {
            inRange = 1;
        }
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 1)
        {
            Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
        }
    }
    sub->behaviourState = 0;
    switch (sub->behaviourState)
    {
    case 10:
    case 11:
        if (sub->linkedObj != NULL)
        {
            sub->scale *= lbl_803E4248;
            *(f32*)((char*)sub->linkedObj + 8) = sub->scale;
        }
        sub->behaviourState = 0xb;
        if (Vec_distance((f32*)((char*)obj + 0x18), (f32*)(player + 0x18)) < (f32)def->innerRadius &&
            (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
        {
            sub->behaviourState = 7;
            return 4;
        }
        break;
    case 0:
    case 8:
        animUpdate->hitVolumePair &= ~0x2;
        yaw = Obj_GetYawDeltaToObject((int)obj, player, 0);
        fn_8003ADC4((GameObject*)(obj), (int*)player, sub->lookBlock, 0x28, 0, 3);
        ((GameObject*)obj)->anim.rotX += (s16)yaw / 8;
        if (inRange != 0)
        {
            animUpdateBytes[0x90] |= 4;
        }
        else
        {
            animUpdateBytes[0x90] = 8;
        }
        break;
    case 5:
        animUpdate->hitVolumePair &= ~0x2;
        yaw = Obj_GetYawDeltaToObject((int)obj, getTrickyObject(), 0);
        fn_8003ADC4((GameObject*)(obj), getTrickyObject(), sub->lookBlock, 0x28, 0, 3);
        ((GameObject*)obj)->anim.rotX += (s16)yaw / 8;
        break;
    }
    return 0;
}

/* Full runner brain - despawn on its gamebit, run the captured/timer flow,
 * follow its rom curve while fleeing, hand off to the nearest sandworm, and
 * once freed steer home to the roost point. */
#pragma opt_common_subs off
void babycloudrunner_update(int* obj)
{
    char* player;
    BabyCloudRunnerState* sub;
    BabyCloudRunnerPlacement* def;
    int found;
    BabyCloudRunnerPlacement* def2;
    BabyCloudRunnerState* sub2;
    int* near;
    int inRange;
    RunnerTarget tgt;
    int mode;
    f32 radius;
    def = *(BabyCloudRunnerPlacement**)&((GameObject*)obj)->anim.placementData;
    sub = ((GameObject*)obj)->extra;
    player = (char*)Obj_GetPlayerObject();
    getTrickyObject();
    if (mainGetBit(def->runnerGameBit) != 0)
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        sub->flags22C &= ~1;
        Obj_RemoveFromUpdateList(obj);
        ObjGroup_RemoveObject(obj, BABYCLOUDRUNNER_OBJGROUP_SECONDARY);
        ObjGroup_RemoveObject(obj, BABYCLOUDRUNNER_OBJGROUP);
    }
    if (sub->runnerState == 2 && mainGetBit(0x66) != 0)
    {
        (*gObjectTriggerInterface)->runSequence(6, obj, -1);
        (*gGameUIInterface)->airMeterSetShutdown();
    }
    else if (fn_80080150(&sub->unk00) != 0)
    {
        sub->flags22C |= 1;
        sub->behaviourState = 0;
        if (((GameObject*)obj)->unkF4 < 0)
        {
            if (def->runnerGameBit != -1)
            {
                mainSetBits(def->runnerGameBit, 1);
            }
            ObjHits_DisableObject(obj);
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            sub->flags22C &= ~1;
            Obj_RemoveFromUpdateList(obj);
            ObjGroup_RemoveObject(obj, BABYCLOUDRUNNER_OBJGROUP_SECONDARY);
            ObjGroup_RemoveObject(obj, BABYCLOUDRUNNER_OBJGROUP);
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
        else
        {
            ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - 1;
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        if (sub->runnerState == 0)
        {
            mode = 0x19;
            if ((*gRomCurveInterface)->initCurve(sub->curveWalker, obj, lbl_803E424C, &mode, 0) == 0)
            {
                sub->runnerState = 1;
                storeZeroToFloatParam(&sub->countdownTimer);
            }
        }
        else
        {
            if (randFn_80080100(500) != 0)
            {
                u16 sfxId = ((s16*)sub->mutterSfxTable)[randomGetRange(0, 3)];
                objAudioFn_80039270((int)obj, sub->audioBlock, sfxId);
            }
            objAnimFn_80038f38((GameObject*)obj, (char*)sub->audioBlock);
            if (sub->runnerState == 1 || sub->runnerState == 2)
            {
                f32 speed = sub->curveSpeed;
                Obj_UpdateRomCurveFollowVelocity((GameObject*)obj, (RomCurveWalker*)sub->curveWalker, speed,
                                                 lbl_803E4238 * speed, lbl_803E4250 * speed, 1);
                Obj_SmoothTurnAnglesTowardVelocity((GameObject*)obj, (const Vec3f*)&((GameObject*)obj)->anim.velocityX,
                                                   0x1e, lbl_803E4238, lbl_803E4254);
                objMove((GameObject*)obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
                        ((GameObject*)obj)->anim.velocityZ);
                if (sub->runnerState == 1)
                {
                    if (sub->runnerIndex != -1 && mainGetBit(sub->runnerIndex + 0xb2a) != 0)
                    {
                        sub->runnerState = 2;
                        mainSetBits(0x66, 0);
                        (*gGameUIInterface)
                            ->initAirMeter(gBabyCloudRunnerAirMeterValues[sub->runnerIndex],
                                           BABYCLOUDRUNNER_AIRMETER_BGTEXTURE);
                        s16toFloat((int)&sub->countdownTimer, (s16)gBabyCloudRunnerAirMeterValues[sub->runnerIndex]);
                    }
                    fn_8019E3F4(obj);
                    return;
                }
                if (sub->runnerState == 2)
                {
                    near = (int*)ObjGroup_FindNearestObject(BABYCLOUDRUNNER_OBJGROUP, obj, 0);
                    if (near != NULL &&
                        Vec_distance(&((GameObject*)near)->anim.worldPosX, (f32*)((char*)sub + 0x18)) < gBabyCloudRunnerTargetNearDist)
                    {
                        sandworm_turnTowardTargetAnim((int)obj, (int)near, sub, 0);
                        if (Vec_distance(&((GameObject*)Obj_GetPlayerObject())->anim.worldPosX,
                                         &((GameObject*)near)->anim.worldPosX) >
                            gBabyCloudRunnerPlayerFarDist)
                        {
                            fn_8014C66C(near, obj);
                            if (((GameObject*)obj)->anim.currentMove != 0xd)
                            {
                                ObjAnim_SetCurrentMove((int)obj, 0xd, ((GameObject*)obj)->anim.currentMoveProgress, 0);
                            }
                            ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E422C, timeDelta,
                                                                                      0);
                        }
                        else
                        {
                            fn_8014C66C(near, Obj_GetPlayerObject());
                        }
                    }
                    else
                    {
                        if (near != NULL)
                        {
                            fn_8014C66C(near, Obj_GetPlayerObject());
                        }
                    }
                    fn_8019E3F4(obj);
                }
            }
            inRange = Vec_distance(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18)) <
                      (f32)(def->innerRadius / 2);
            if (sub->runnerState == 2)
            {
                radius = (f32)def->outerRadius;
                if (fn_80080150(&sub->countdownTimer) != 0)
                {
                    if ((*(u16*)((char*)Obj_GetPlayerObject() + 0xb0) & BABYCLOUDRUNNER_OBJFLAG_PARENT_SLACK) == 0 &&
                        timerCountDown(&sub->countdownTimer) != 0)
                    {
                        (*gObjectTriggerInterface)->runSequence(6, obj, -1);
                        (*gGameUIInterface)->airMeterSetShutdown();
                        return;
                    }
                    (*gGameUIInterface)->runAirMeter((int)sub->countdownTimer);
                }
                if (inRange == 0 && (void*)ObjGroup_FindNearestObject(BABYCLOUDRUNNER_OBJGROUP, obj, &radius) != NULL)
                {
                    inRange = 1;
                }
                if (mainGetBit(sub->runnerIndex + 0xb2e) != 0)
                {
                    sub->runnerState = 3;
                    (*gGameUIInterface)->airMeterSetShutdown();
                    Sfx_PlayFromObject((int)obj, SFXTRIG_menuups16k);
                    storeZeroToFloatParam(&sub->countdownTimer);
                }
            }
            else
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
                sub2 = ((GameObject*)obj)->extra;
                {
                    char* pp = (char*)Obj_GetPlayerObject();
                    def2 = *(BabyCloudRunnerPlacement**)&((GameObject*)obj)->anim.placementData;
                    found = 0;
                    if (Vec_distance((f32*)(pp + 0x18), &((GameObject*)obj)->anim.worldPosX) < (f32)def2->innerRadius && sub2->runnerState == 3 &&
                        (((GameObject*)obj)->objectFlags & BABYCLOUDRUNNER_OBJFLAG_PARENT_SLACK) == 0)
                    {
                        found = 1;
                    }
                }
                if (found != 0)
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
                }
                else
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                }
            }
            if (sub->runnerState == 3)
            {
                if (!((WormSpitByte*)&sub->spitFlags)->_p0)
                {
                    tgt.x = def->base.posX;
                    tgt.y = def->base.posY;
                    tgt.z = def->base.posZ;
                    tgt.a = sub->roostYaw;
                    tgt.b = 0;
                    tgt.c = 0;
                    ((GameObject*)obj)->anim.rotY = 0;
                    ((GameObject*)obj)->anim.rotZ = 0;
                    if (dll_2E_func0D(obj, &tgt, lbl_803DBE40, -1, &lbl_803DBE44, &lbl_803DBE48) != 0)
                    {
                        ((WormSpitByte*)&sub->spitFlags)->_p0 = 1;
                        mainSetBits(0x66, 0);
                    }
                    ObjAnim_AdvanceCurrentMove((int)obj, lbl_803DBE44, timeDelta, 0);
                }
                else
                {
                    if (inRange != 0)
                    {
                        (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                        sub->unkB0 = 1;
                    }
                    sandworm_turnTowardTargetAnim((int)obj, (int)Obj_GetPlayerObject(), sub, 1);
                    if (ObjAnim_AdvanceCurrentMove((int)obj, sub->animSpeed, timeDelta,
                                                                                  0) != 0)
                    {
                        if (randFn_80080100(2) != 0)
                        {
                            ObjAnim_SetCurrentMove((int)obj, 2, lbl_803E4218, 0);
                        }
                        else
                        {
                            ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E4218, 0);
                        }
                    }
                }
            }
        }
    }
}
#pragma opt_common_subs reset

int gBabyCloudRunnerAirMeterValues[4] = {0x1770, 0x2EE0, 0x2EE0, 0x3E80};
