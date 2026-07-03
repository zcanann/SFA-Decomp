/*
 * sandwormBoss.c - 10-DLL container (DLL 0x14A CFPowerBase .. 0x157
 * SpiritDoorSpirit), TU [8019D578-801A0B14). DLLs 0x148 and 0x149 are
 * defined in dll_0148_cfguardian.c and dll_0149_cfwindlift.c; their
 * definitions here are collapsed to forward prototypes.
 */
#include "main/dll/cfguardian_state.h"
#include "main/dll/wormspitbyte_struct.h"
#include "main/dll/cfprisonunclestate_struct.h"
#include "main/dll/babycloudrunnerflags_struct.h"
#include "main/dll/gcrobotlightbeastate_struct.h"
#include "main/dll/cfprisonguardstate_struct.h"
#include "main/dll/cfpowerbasestate_struct.h"
#include "main/dll/cfmaincrystalstate_types.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objseq.h"
#include "main/audio/sfx.h"
#include "main/sfa_shared_decls.h"

#define BABYCLOUDRUNNER_OBJFLAG_PARENT_SLACK 0x1000
extern int randomGetRange(int lo, int hi);
extern u32 ObjHits_DisableObject();
extern u32 ObjHits_EnableObject();
extern int ObjGroup_FindNearestObject();
extern u64 ObjGroup_RemoveObject();
extern u32 ObjGroup_AddObject();
extern void ObjMsg_AllocQueue(void* obj, int capacity);
extern int Obj_GetYawDeltaToObject();
extern u32 objAnimFn_80038f38();
extern void objRenderFn_8003b8f4(f32);
extern u32 DAT_802c2a58;
extern u32 DAT_802c2a5c;
extern u32 DAT_802c2a60;
extern u32 DAT_802c2a64;
extern f32 lbl_803DC074;
extern f32 lbl_803E4EC0;
extern f32 lbl_803E4228;
extern f32 lbl_803E4DA8;
extern f32 lbl_803E4DBC;
extern f32 lbl_803E4DC0;
extern f32 lbl_803E4EB0;
extern f32 lbl_803E4EC4;
extern f32 lbl_803E4EC8;
extern f32 lbl_803E4ECC;
extern f32 lbl_803E4F58;
extern f32 lbl_803E4F5C;
extern f32 lbl_803E4F60;
extern f32 lbl_803E4F64;
extern f32 lbl_803E4F68;
extern f32 lbl_803E4F6C;
extern f32 lbl_803E4F70;
extern f32 lbl_803E4F74;
extern f32 lbl_803E422C;
extern f32 lbl_803E4244;
extern f32 lbl_803E4258;
extern u8 gBabyCloudRunnerMutterSfxTable;
extern u8 gBabyCloudRunnerMutterSfxTableSpecial;
extern void storeZeroToFloatParam(void* p);
extern u32 GameBit_Get(int eventId);
extern int Obj_RemoveFromUpdateList(int* obj);
extern void* Obj_GetPlayerObject(void);
extern void fn_8003ADC4(int* a, int* b, void* c, int d, int e, int f);
extern f32 lbl_803E4218;
extern f32 lbl_803E423C;
extern f32 lbl_803E4240;
extern f32 timeDelta;
extern f32 Vec_distance(void* a, void* b);
extern f32 s16toFloat(int a, int b);
extern void objAudioFn_800393f8(int obj, void* p, int a, int b, int c, int d);



extern f32 lbl_803E4230;
extern f32 lbl_803E4234;
extern f32 lbl_803DBE4C;
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern void* getTrickyObject(void);
extern f32 lbl_803E4248;
extern int fn_80080150(void* p);
extern int timerCountDown(void* p);

extern void Obj_UpdateRomCurveFollowVelocity(int* obj, void* p, f32 a, f32 b, f32 c, int d);
extern void Obj_SmoothTurnAnglesTowardVelocity(int* obj, void* p, int n, f32 a, f32 b);
extern void fn_8014C66C(int* a, void* b);
extern int dll_2E_func0D(int* obj, void* p, f32 f, int c, f32* a, f32* b);
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

void babycloudrunner_init_OLD_v1_1(int obj)
{
    u32* state;

    state = ((GameObject*)obj)->extra;
    *state = 0;
    state[1] = 0;
    ObjHits_EnableObject(obj);
    ((GameObject*)obj)->anim.alpha = 0x80;
    return;
}

/* Per-object extra state for the baby CloudRunner
 * (babycloudrunner_getExtraSize == 0x248). */
typedef struct BabyCloudRunnerState
{
    f32 unk00;
    u8 pad04[0x38]; /* 0x18: position used for the sandworm handoff */
    u8 lookBlock[0x30]; /* 0x3c: fn_8003ADC4 head-track block */
    u8 audioBlock[0x3c]; /* 0x6c: objAudioFn block */
    f32 animSpeed;
    f32 scale; /* 0xac: copied to the linked object's scale */
    int unkB0;
    int unkB4;
    int unkB8;
    int unkBC;
    int turnLatch; /* 0xc0: sandworm_turnTowardTargetAnim turn/idle move latch */
    int behaviourState; /* 0xc4: def[0x1c]; SeqFn 0..0xb dispatch */
    u8 padC8[4];
    int unkCC;
    s16 roostYaw; /* 0xd0: heading captured at init */
    u8 padD2[0x42];
    void* linkedObj; /* 0x114 */
    u8 pad118[0xc];
    u8 curveWalker[0x108]; /* 0x124: rom-curve follow block */
    u8 flags22C; /* 1 = alive/active */
    u8 pad22D[3];
    int runnerState; /* 0x230: 0 curve-seek, 1 follow, 2 chased, 3 freed */
    int runnerIndex; /* 0x234: gamebit base index, -1 keyed off */
    f32 countdownTimer; /* 0x238 */
    f32 curveSpeed; /* 0x23c */
    void* mutterSfxTable; /* 0x240 */
    u8 spitFlags; /* 0x244: BabyCloudrunnerFlags / WormSpitByte overlay */
    u8 pad245[3];
} BabyCloudRunnerState;

STATIC_ASSERT(sizeof(BabyCloudRunnerState) == 0x248);

/* Placement record for the baby cloud runner (ObjPlacement head + tuning). */
typedef struct BabyCloudRunnerPlacement
{
    ObjPlacement base; /* 0x00: posX/posY/posZ at 0x08/0x0c/0x10 = roost point */
    s16 outerRadius; /* 0x18: outer trigger radius */
    s16 innerRadius; /* 0x1a: inner trigger radius (halved for proximity tests) */
    u8 behaviourState; /* 0x1c: initial BabyCloudRunnerState.behaviourState */
    u8 initialYaw; /* 0x1d: << 8 -> rotX */
    s16 enableBit; /* 0x1e: gamebit set on capture */
    u8 pad20[2];
    s16 runnerGameBit; /* 0x22: despawn gamebit; -0x2fc -> runnerIndex */
} BabyCloudRunnerPlacement;

STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, outerRadius) == 0x18);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, innerRadius) == 0x1a);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, behaviourState) == 0x1c);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, initialYaw) == 0x1d);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, enableBit) == 0x1e);
STATIC_ASSERT(offsetof(BabyCloudRunnerPlacement, runnerGameBit) == 0x22);

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
    ObjGroup_AddObject(obj, 3);
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
    if (GameBit_Get(def->runnerGameBit) != 0)
    {
        ObjHits_DisableObject(obj);
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        sub->flags22C = (u8)(sub->flags22C & ~1);
        Obj_RemoveFromUpdateList(obj);
        ObjGroup_RemoveObject(obj, 3);
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
            ObjGroup_AddObject(obj, 0x20);
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
        objRenderFn_8003b8f4(lbl_803E4228);
    }
    return;
}

#pragma peephole on

/* Per-object extra state for the CloudRunner guardian
 * (cfguardian_getExtraSize == 0xa9c). */
STATIC_ASSERT(sizeof(CfGuardianState) == 0xa9c);

/* EN v1.0 0x8019E568  size: 352b  sandworm_turnTowardTargetAnim: turn toward the target by
 * a fraction of the yaw delta; when roughly aligned play/advance the idle
 * move, otherwise start or speed-scale the turn move by the delta. */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void sandworm_turnTowardTargetAnim(int a, int b, u8* c, int d)
{
    int shifted;
    fn_8003ADC4((int*)a, (int*)b, c + 0x3c, 0x28, 0, 3);
    shifted = Obj_GetYawDeltaToObject(a, b, 0);
    *(s16*)a += (shifted >>= 3);
    if (d == 0) return;
    if ((s16)shifted > -200 && (s16)shifted < 200)
    {
        if (((BabyCloudRunnerState*)c)->turnLatch != 0)
        {
            ((BabyCloudRunnerState*)c)->turnLatch = 0;
            ObjAnim_SetCurrentMove(a, 0, lbl_803E4218, 0);
        }
        else
        {
            ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(a, lbl_803E423C, timeDelta, 0);
        }
    }
    else
    {
        if (((BabyCloudRunnerState*)c)->turnLatch == 0)
        {
            ((BabyCloudRunnerState*)c)->turnLatch = 1;
            ObjAnim_SetCurrentMove(a, 9, lbl_803E4218, 0);
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
            ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(a, (f32)(s16)t / lbl_803E4240, timeDelta, 0);
        }
    }
}
#pragma opt_common_subs reset
#pragma peephole on
#pragma dont_inline reset

/* EN v1.0 0x8019E6C8  size: 316b  babycloudrunner_func0B: when the player
 * gets within the trigger radius and the runner is in state 3, fire its
 * burst (notify, bump the counter, set the gamebit); otherwise just play
 * the idle audio cue. */
#pragma peephole off
int babycloudrunner_func0B(void* p)
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
    if (Vec_distance((char*)player + 0x18, (char*)obj + 0x18) < (f32)(s16)r->innerRadius)
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
        GameBit_Set(q->enableBit, 1);
        ((GameObject*)obj)->unkF4 = 0;
        return 1;
    }
    objAudioFn_800393f8((int)obj, (char*)sub + 0x6c, 0x296, 0x1000, -1, 1);
    Sfx_PlayFromObject((int)obj, SFXsk_baptr9_c);
    return 0;
}
#pragma peephole reset

/* Per-object extra state for the CloudRunner main crystal
 * (cfmaincrystal_getExtraSize == 0x160). */

STATIC_ASSERT(sizeof(CfMainCrystalState) == 0x160);

/* Per-object extra state for the CloudRunner power base
 * (cfpowerbase_getExtraSize == 0x6). */

STATIC_ASSERT(sizeof(CfPowerBaseState) == 0x6);

/* Per-object extra state for the CloudRunner prison guard
 * (cfprisonguard_getExtraSize == 0x3c). */

STATIC_ASSERT(sizeof(CfPrisonGuardState) == 0x3c);

/* Per-object extra state for the CloudRunner prison uncle
 * (cfprisonuncle_getExtraSize == 0xa8). */

STATIC_ASSERT(sizeof(CfPrisonUncleState) == 0xa8);

/* Per-object extra state for the robot light beacon
 * (gcrobotlightbea_getExtraSize == 0xc). */

STATIC_ASSERT(sizeof(GcRobotLightBeaState) == 0xc);

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


int babycloudrunner_getExtraSize(void) { return 0x248; }
int cfprisonguard_getExtraSize(void);

int babycloudrunner_getObjectTypeId(void) { return 0; }


#pragma scheduling off
#pragma peephole off
int babycloudrunner_setScale(int* obj)
{
    BabyCloudRunnerState* state = ((GameObject*)obj)->extra;
    return !(state->flags22C & 1);
}


void babycloudrunner_free(int* obj)
{
    ObjGroup_RemoveObject(obj, 32);
    ObjGroup_RemoveObject(obj, 3);
}


/* EN v1.0 0x8019E3F4  size: 372b  fn_8019E3F4: pick the burrow/surface move
 * from the vertical speed, clamp the playback rate, latch the spit SFX
 * while surfacing fast, and advance the current move. */
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
                Sfx_PlayFromObject((int)obj, SFXand_spitout);
                ((WormSpitByte*)&sub->spitFlags)->spitLatch = 1;
            }
        }
        else
        {
            ((WormSpitByte*)&sub->spitFlags)->spitLatch = 0;
        }
    }
    ((int(*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)((int)obj, speed, timeDelta, 0);
    return 1;
}
#pragma opt_common_subs reset
#pragma dont_inline reset

/* EN v1.0 0x8019E81C  size: 920b  babycloudrunner_SeqFn: range-check the
 * runner against the player and its trigger radii, chirp for queued cues,
 * then steer toward the player (or Tricky) per the current behaviour state. */
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
    player = Obj_GetPlayerObject();
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
        char* pp = Obj_GetPlayerObject();
        BabyCloudRunnerPlacement* def2 = *(BabyCloudRunnerPlacement**)&((GameObject*)obj)->anim.placementData;
        int found = 0;
        if (Vec_distance(pp + 0x18, (char*)((int)obj + 0x18)) < (f32)def2->innerRadius
            && sub2->runnerState == 3
            && (((GameObject*)obj)->objectFlags & BABYCLOUDRUNNER_OBJFLAG_PARENT_SLACK) == 0)
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
        if ((void*)ObjGroup_FindNearestObject(3, obj, &radius) != NULL)
        {
            inRange = 1;
        }
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 1)
        {
            Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
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
        if (Vec_distance((char*)obj + 0x18, player + 0x18) < (f32)def->innerRadius
            && (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
        {
            sub->behaviourState = 7;
            return 4;
        }
        break;
    case 0:
    case 8:
        animUpdate->hitVolumePair &= ~0x2;
        yaw = Obj_GetYawDeltaToObject((int)obj, player, 0);
        fn_8003ADC4(obj, (int*)player, (char*)sub + 0x3c, 0x28, 0, 3);
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
        fn_8003ADC4(obj, getTrickyObject(), (char*)sub + 0x3c, 0x28, 0, 3);
        ((GameObject*)obj)->anim.rotX += (s16)yaw / 8;
        break;
    }
    return 0;
}

typedef struct
{
    s16 a, b, c;
    u8 pad[6];
    f32 x, y, z;
} RunnerTarget;

/* EN v1.0 0x8019EC34  size: 1908b  babycloudrunner_update: full runner brain -
 * despawn on its gamebit, run the captured/timer flow, follow its rom curve
 * while fleeing, hand off to the nearest sandworm, and once freed steer home
 * to the roost point. */
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
    player = Obj_GetPlayerObject();
    getTrickyObject();
    if (GameBit_Get(def->runnerGameBit) != 0)
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        sub->flags22C &= ~1;
        Obj_RemoveFromUpdateList(obj);
        ObjGroup_RemoveObject(obj, 0x20);
        ObjGroup_RemoveObject(obj, 3);
    }
    if (sub->runnerState == 2 && GameBit_Get(0x66) != 0)
    {
        (*gObjectTriggerInterface)->runSequence(6, obj, -1);
        (*gGameUIInterface)->airMeterSetShutdown();
    }
    else if (fn_80080150(sub) != 0)
    {
        sub->flags22C |= 1;
        sub->behaviourState = 0;
        if (((GameObject*)obj)->unkF4 < 0)
        {
            if (def->runnerGameBit != -1)
            {
                GameBit_Set(def->runnerGameBit, 1);
            }
            ObjHits_DisableObject(obj);
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            sub->flags22C &= ~1;
            Obj_RemoveFromUpdateList(obj);
            ObjGroup_RemoveObject(obj, 0x20);
            ObjGroup_RemoveObject(obj, 3);
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
            if ((*gRomCurveInterface)->initCurve((char*)sub + 0x124, obj, lbl_803E424C, &mode, 0) == 0)
            {
                sub->runnerState = 1;
                storeZeroToFloatParam((char*)sub + 0x238);
            }
        }
        else
        {
            if (randFn_80080100(500) != 0)
            {
                u16 sfxId = ((s16*)sub->mutterSfxTable)[randomGetRange(0, 3)];
                objAudioFn_80039270((int)obj, (char*)sub + 0x6c, sfxId);
            }
            objAnimFn_80038f38((int)obj, (char*)sub + 0x6c);
            if (sub->runnerState == 1 || sub->runnerState == 2)
            {
                f32 speed = sub->curveSpeed;
                Obj_UpdateRomCurveFollowVelocity(obj, (char*)sub + 0x124, speed, lbl_803E4238 * speed,
                                                 lbl_803E4250 * speed, 1);
                Obj_SmoothTurnAnglesTowardVelocity(obj, (char*)((int)obj + 0x24), 0x1e, lbl_803E4238, lbl_803E4254);
                objMove((int)obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY, ((GameObject*)obj)->anim.velocityZ);
                if (sub->runnerState == 1)
                {
                    if (sub->runnerIndex != -1 && GameBit_Get(sub->runnerIndex + 0xb2a) != 0)
                    {
                        sub->runnerState = 2;
                        GameBit_Set(0x66, 0);
                        (*gGameUIInterface)->initAirMeter(gBabyCloudRunnerAirMeterValues[sub->runnerIndex], 0x5d1);
                        s16toFloat((int)((char*)sub + 0x238), (s16)gBabyCloudRunnerAirMeterValues[sub->runnerIndex]);
                    }
                    fn_8019E3F4(obj);
                    return;
                }
                if (sub->runnerState == 2)
                {
                    near = (int*)ObjGroup_FindNearestObject(3, obj, 0);
                    if (near != NULL && Vec_distance((char*)((int)near + 0x18), (char*)sub + 0x18) < gBabyCloudRunnerTargetNearDist)
                    {
                        sandworm_turnTowardTargetAnim((int)obj, (int)near, (u8*)sub, 0);
                        if (Vec_distance((char*)Obj_GetPlayerObject() + 0x18, (char*)near + 0x18) > gBabyCloudRunnerPlayerFarDist)
                        {
                            fn_8014C66C(near, obj);
                            if (((GameObject*)obj)->anim.currentMove != 0xd)
                            {
                                ObjAnim_SetCurrentMove((int)obj, 0xd, ((GameObject*)obj)->anim.currentMoveProgress, 0);
                            }
                            ((int (*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)(
                                (int)obj, lbl_803E422C, timeDelta, 0);
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
            inRange = Vec_distance((char*)((int)obj + 0x18), player + 0x18) < (f32)(def->innerRadius / 2);
            if (sub->runnerState == 2)
            {
                radius = (f32)def->outerRadius;
                if (fn_80080150((char*)sub + 0x238) != 0)
                {
                    if ((*(u16*)((char*)Obj_GetPlayerObject() + 0xb0) & 0x1000) == 0 && timerCountDown(
                        (char*)sub + 0x238) != 0)
                    {
                        (*gObjectTriggerInterface)->runSequence(6, obj, -1);
                        (*gGameUIInterface)->airMeterSetShutdown();
                        return;
                    }
                    (*gGameUIInterface)->runAirMeter((int)sub->countdownTimer);
                }
                if (inRange == 0 && (void*)ObjGroup_FindNearestObject(3, obj, &radius) != NULL)
                {
                    inRange = 1;
                }
                if (GameBit_Get(sub->runnerIndex + 0xb2e) != 0)
                {
                    sub->runnerState = 3;
                    (*gGameUIInterface)->airMeterSetShutdown();
                    Sfx_PlayFromObject((int)obj, SFXsp_lf_mutter4);
                    storeZeroToFloatParam((char*)sub + 0x238);
                }
            }
            else
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
                sub2 = ((GameObject*)obj)->extra;
                {
                    char* pp = Obj_GetPlayerObject();
                    def2 = *(BabyCloudRunnerPlacement**)&((GameObject*)obj)->anim.placementData;
                    found = 0;
                    if (Vec_distance(pp + 0x18, (char*)obj + 0x18) < (f32)def2->innerRadius
                        && sub2->runnerState == 3
                        && (((GameObject*)obj)->objectFlags & BABYCLOUDRUNNER_OBJFLAG_PARENT_SLACK) == 0)
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
                        GameBit_Set(0x66, 0);
                    }
                    ((int (*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803DBE44, timeDelta, 0);
                }
                else
                {
                    if (inRange != 0)
                    {
                        (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                        sub->unkB0 = 1;
                    }
                    sandworm_turnTowardTargetAnim((int)obj, (int)Obj_GetPlayerObject(), (u8*)sub, 1);
                    if (((int (*)(int, f32, f32, int))ObjAnim_AdvanceCurrentMove)(
                        (int)obj, sub->animSpeed, timeDelta, 0) != 0)
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
