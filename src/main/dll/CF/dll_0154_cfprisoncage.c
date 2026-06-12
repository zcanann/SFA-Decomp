/* DLL 0x0154 — cfprisoncage. TU: 0x801A0614–0x801A0994. */
#include "main/dll/cfguardian_state.h"
#include "main/dll/wormspitbyte_struct.h"
#include "main/dll/cfprisonunclestate_struct.h"
#include "main/dll/babycloudrunnerflags_struct.h"
#include "main/dll/gcrobotlightbeastate_struct.h"
#include "main/dll/cfprisonguardstate_struct.h"
#include "main/dll/cfpowerbasestate_struct.h"
#include "main/dll/cfmaincrystalstate_types.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/objseq.h"

extern undefined8 FUN_80006824();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern undefined4 FUN_8002f6ac();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHitWithPosition();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern void objRenderFn_8003b8f4(f32);
extern undefined4 FUN_8006f7a0();
extern int FUN_8007f924();
extern undefined4 FUN_800e8630();
extern int FUN_801149b8();
extern int FUN_8020a468();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80294d40();

extern undefined4 DAT_802c2a58;
extern undefined4 DAT_802c2a5c;
extern undefined4 DAT_802c2a60;
extern undefined4 DAT_802c2a64;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern f64 DOUBLE_803e4db0;
extern f32 lbl_803DC074;
extern f32 gBoneParticleEffectInterface;
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
extern uint GameBit_Get(int eventId);
extern void fn_8003ADC4(int* a, int* b, void* c, int d, int e, int f);
extern f32 Vec_distance(void* a, void* b);
extern f32 lbl_803E42B0;
extern f32 lbl_803E4280;
extern void objfx_spawnHitEmitterAtPos(f32* p, int a, int b, int c, int d);
extern f32 lbl_803E42B4;







void babycloudrunner_init_OLD_v1_1(int obj)
{
    undefined4* state;

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


void cfguardian_release(void);

/* Per-object extra state for the CloudRunner guardian
 * (cfguardian_getExtraSize == 0xa9c). */
STATIC_ASSERT(sizeof(CfGuardianState) == 0xa9c);

/* EN v1.0 0x801A0614  size: 368b  cfprisoncage_SeqFn: drain the object's message
 * queue (re-arming its gamebit on the keyed message), then sync the
 * lit/active state from gamebit 0x44 and notify on completion. */
#pragma scheduling off
#pragma peephole off
int cfprisoncage_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int msg;
    int v;
    int w = 0;
    u8* sub = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (GameBit_Get(*(s16*)(sub + 0x18)) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x8);
        animUpdate->sequenceControlFlags |= 4;
        return 0;
    }
    if (((GameObject*)obj)->anim.seqId == 0x127)
    {
        return 0;
    }
    while (ObjMsg_Pop(obj, &msg, &v, &w) != 0)
    {
        switch (msg)
        {
        case 0xA0005:
            GameBit_Set(*(s16*)(sub + 0x18), 1);
            break;
        }
    }
    if (GameBit_Get(0x44) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x10);
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x10);
    }
    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0)
    {
        if ((*gGameUIInterface)->isEventReady(0x44) != 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x8);
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
    }
    return 0;
}

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

/* spiritdoorspirit_getExtraSize == 0x1. */

typedef struct CfprisoncageObjectDef
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} CfprisoncageObjectDef;

#pragma scheduling on
#pragma peephole on
void cfprisoncage_free(void)
{
}

void cfprisoncage_release(void)
{
}

void cfprisoncage_initialise(void)
{
}

#pragma scheduling off
#pragma peephole off
void cfprisoncage_update(int* obj)
{
    extern ObjectTriggerInterface** gObjectTriggerInterface;
    int v;
    if (((GameObject*)obj)->unkF4 != 0)
    {
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0x127: v = 0;
            break;
        case 0x128:
        default: v = 1;
            break;
        }
        (*gObjectTriggerInterface)->runSequence(v, obj, -1);
        ((GameObject*)obj)->unkF4 = 0;
    }
}
void spiritdoorspirit_hitDetect(void);

int cfprisoncage_getExtraSize(void) { return 0x0; }
int spiritdoorspirit_getExtraSize(void);

#pragma scheduling on
void cfprisoncage_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E42B0);
}

int cfprisoncage_getObjectTypeId(int* obj)
{
    if (((GameObject*)obj)->anim.seqId == 0x128) return 0x8;
    return 0x0;
}

u32 fn_801A0174(int* obj);

extern int ObjHits_GetPriorityHitWithPosition(int* obj, int a, int b, int c, f32* out_x, f32* out_y, f32* out_z);

#pragma scheduling off
void cfprisoncage_hitDetect(int* obj)
{
    f32 pos_z, pos_y, pos_x;
    if (ObjHits_GetPriorityHitWithPosition(obj, 0, 0, 0, &pos_x, &pos_y, &pos_z) != 0)
    {
        objfx_spawnHitEmitterAtPos(&pos_x, 8, 200, 128, 0);
    }
}

void cfprisoncage_init(int* obj, u8* def)
{
    ObjMsg_AllocQueue(obj, 1);
    *(s16*)obj = (s16)((s32)def[0x1a] << 8);
    ((GameObject*)obj)->unkF4 = 1;
    ((GameObject*)obj)->animEventCallback = (void*)cfprisoncage_SeqFn;
    if (((GameObject*)obj)->anim.seqId == 296)
    {
        if (GameBit_Get(((CfprisoncageObjectDef*)def)->unk18) != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E42B4, 0);
        }
        else
        {
            ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E42B4, 0);
        }
    }
    else
    {
        if (GameBit_Get(((CfprisoncageObjectDef*)def)->unk18) != 0)
        {
            (*gObjectTriggerInterface)->preempt((int)obj, 60);
        }
    }
}

void windlift_free(int* obj);
