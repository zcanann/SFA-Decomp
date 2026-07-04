/*
 * cfguardian (DLL 0x148) - the Queen CloudRunner of the CloudRunner
 * Fortress. cfguardian_updateMain drives her quest arc: she is caged
 * until the player rescues her children, then is released and flies an
 * escape curve to roost. Once the children are all saved (the
 * "convergence" cutscene that opens the treasure room) she lands, flies
 * to the talk spots and greets the player across two dialogue loops, then
 * makes her final flight out. The endgame cutscene perches run her
 * see-off, where she awards the spell stone. Helpers steer her along rom
 * curves (cfguardianSteerToward) and play per-event sfx
 * (cfguardianPlayEventSfx). Carved from the front of the sandwormBoss
 * container; the 0x148 TU truly starts in DR/hightop.c (documented cut in
 * docs/boundary_audit.md).
 */

#include "main/game_object.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_0015_curves.h"
#include "main/obj_placement.h"
#include "main/dll/cfguardian_state.h"
#include "main/camera_interface.h"
#include "main/game_ui_interface.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/dll/player_status.h"
#include "main/objseq.h"
#include "main/object_descriptor.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/dll/CF/dll_0148_cfguardian.h"

#define CFGUARDIAN_OBJGROUP 0x16

#define PAD_BUTTON_A 0x100

/* steer-target header passed to cfguardianSteerToward: a yaw plus a world point */
typedef struct
{
    s16 angle;
    s16 pad[5];
    f32 x;
    f32 y;
    f32 z;
} RomCurveTarget;

/* the rom-curve walker block the guardian flies along (sub->pathBlock);
   only the fields this DLL touches are mapped. */
typedef struct CfCurveWalker
{
    u8 pad00[0x10];
    int atEnd;   /* 0x10: non-zero once the curve runs out */
    u8 pad14[0x54];
    f32 posX;    /* 0x68: sampled curve position */
    f32 posY;    /* 0x6C */
    f32 posZ;    /* 0x70 */
} CfCurveWalker;

/* hitbox/heading template (gCfGuardianHitboxTemplateA/CC), copied to the stack at init */
typedef struct
{
    s16 v[5];
} GuardianVec;

/* active/idle heading-pair template (gCfGuardianHeadingTemplate) used by cfguardian_SeqFn */
typedef struct
{
    int a, b, c, d;
} GuardianMsg;

typedef struct CfGuardianMapData
{
    ObjPlacement base;
    s8 rotXByte; /* 0x18: initial rotX in 1/256 turns */
    s8 variant;  /* 0x19: 1 = the convergence-gated guardian */
} CfGuardianMapData;

STATIC_ASSERT(sizeof(CfGuardianState) == 0xa9c);
STATIC_ASSERT(offsetof(CfGuardianMapData, variant) == 0x19);

/* cfguardianPlayEventSfx/cfguardianFlyAlongPath are defined below taking
 * obj as an int; cfguardian_updateMain calls them through these pointer-first
 * fn-ptr casts. */
typedef void (*CfPlayEventSfxFn)(int* obj, void* evbuf, void* sfxIds);
typedef int (*CfFlyAlongPathFn)(int* obj, void* path, f32 f, int phase, void* spd);

/* sub->flagsA9B bits */
#define GUARDIAN_FLAG_MOVE_LATCHED 0x1 /* a one-shot move is running */
#define GUARDIAN_FLAG_PATH_FLYING 0x2  /* flying a rom curve this tick */
#define GUARDIAN_FLAG_HOMING 0x4       /* steering toward the talk spot */

/* sub->questState: the Queen's quest arc, driven by the
   cfguardian_updateMain switch and mirrored to game bit 0x4b. The
   moment-to-moment AI/chatter handling lives in the shared baddie
   controller dll_2E_func03; these states are the scripted
   release-rescue-and-see-off progression. */
enum
{
    CFGUARDIAN_DORMANT = 0,          /* asleep until the quest starts (0x94f) */
    CFGUARDIAN_CAGED = 1,            /* caged, waiting for it to open (0x4e) */
    CFGUARDIAN_FLY_ESCAPE = 2,       /* flying the escape curve out of the cage */
    CFGUARDIAN_RELEASE_SEQ = 3,      /* runs the release sequence once */
    CFGUARDIAN_ROOST = 4,            /* roosting until the convergence cutscene */
    CFGUARDIAN_LANDING = 6,          /* free-fall, settle to the ground at home */
    CFGUARDIAN_FLY_TO_TALK = 7,      /* flying the curve to the talk spot */
    CFGUARDIAN_TALK_1 = 8,           /* first dialogue loop; 0x43 advances */
    CFGUARDIAN_TALK_2 = 9,           /* second dialogue loop; 0x4be advances */
    CFGUARDIAN_FLY_OUT = 0xa,        /* final flight out */
    CFGUARDIAN_VANISH = 0xb,         /* fades out and stops updating */
    CFGUARDIAN_CUTSCENE_PERCH_A = 0xc, /* see-off cutscene perch, sequence 0xb on cue */
    CFGUARDIAN_CUTSCENE_PERCH_B = 0xd, /* see-off cutscene perch, sequence 0xa on cue */
    CFGUARDIAN_PARKED = 0xe,         /* parked, idle chatter only */
    CFGUARDIAN_PARKED_HIDDEN = 0xf   /* parked and hidden */
};

/* sub->chatterState: idle-chatter handshake (1 ready to pick a line, 2 a
   line is playing). */
#define GUARDIAN_CHATTER_READY 1
#define GUARDIAN_CHATTER_PLAYING 2

/* the guardian's anim "fly/chase" move */
#define GUARDIAN_MOVE_FLY 0x1a

/* game bits this DLL reads/writes. Most are cross-TU quest flags
   without established names; the few it clearly owns are named here. */
#define GAMEBIT_GUARDIAN_CONVERGENCE 0x57 /* children-rescued convergence cutscene is live */
#define GAMEBIT_GUARDIAN_QUEST_START 0x94f
#define GAMEBIT_GUARDIAN_CAGE_OPEN 0x4e   /* this guardian's clouddungeon cage */
#define GAMEBIT_GUARDIAN_PRISONGUARD_STAND_DOWN 0x48
#define GAMEBIT_GUARDIAN_RELEASED 0x60
#define GAMEBIT_GUARDIAN_LANDED 0x8e9     /* the landing sequence finished */
#define GAMEBIT_GUARDIAN_QUEST_STATE 0x4b /* mirror of sub->questState */

/* sfx ids */
#define GUARDIAN_SFX_FLAP 0xe1
#define GUARDIAN_SFX_CHATTER 0xdf

extern void Sfx_PlayFromObject(int obj, u16 sfxId);
extern int hitDetectFn_800658a4(int a, f32 b, f32 val, f32 d, f32* out, int e);
extern f32 lbl_803E4110;
extern f32 lbl_803E4120;
extern f32 lbl_803E4124;
extern f32 lbl_803E4128;
extern f32 lbl_803E412C;
extern f32 lbl_803E4130;
extern f32 lbl_803E4134;
extern f32 lbl_803E4138;
extern f32 lbl_803E413C;
extern f32 lbl_803E4140;
extern f32 lbl_803E4144;
extern f32 lbl_803E4148;
extern f32 lbl_803E414C;
extern f32 lbl_803E4150;
extern f32 lbl_803E4154;
extern f32 lbl_803E4158;
extern f32 lbl_803E415C;


extern int Curve_AdvanceAlongPath(int p1);
extern int getAngle(float y, float x);
extern int ObjHits_EnableObject();
extern int ObjGroup_FindNearestObject(int group, u32 obj, float* maxDistance);
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern void ObjGroup_AddObject(u32 obj, int group);
extern void ObjMsg_AllocQueue(void* obj, int capacity);
extern bool ObjTrigger_UpdateIdBlockFlag(int obj);
extern int ObjTrigger_IsSet();
extern int objAnimFn_80038f38();
extern void objRenderFn_8003b8f4(f32);
extern int dll_2E_func03();
extern u32 GameBit_Get(int eventId);
extern int Obj_RemoveFromUpdateList(int* obj);
extern GuardianVec gCfGuardianHitboxTemplateA; /* hitbox template copied at init */
extern GuardianVec gCfGuardianHitboxTemplateB; /* hitbox template copied at init */
extern int gCfGuardianSeqStreamTable[][2];    /* chatter sequence-stream table, 0xf states */
extern void dll_2E_func0A(int a, int* obj);
extern void dll_2E_func05(int* obj, u8* sub, int c, int d, int e);
extern void dll_2E_func08(u8* sub, int b, int c);
extern void dll_2E_func09(u8* sub, void* a, void* b, int c);
extern void objSeqInitFn_80080078(void* p, int n);
extern GuardianMsg gCfGuardianHeadingTemplate; /* active/idle heading-pair template (cfguardian_SeqFn) */
extern int animatedObjGetSeqId(int* p);
extern void saveGame_saveObjectPos(int obj);
extern void* Obj_GetPlayerObject(void);
extern void playerAddRemoveMagic(void* player, int n);
extern f32 timeDelta;
extern void objAudioFn_800393f8(int obj, void* p, int a, int b, int c, int d);
extern u8 framesThisStep;
extern int cfguardian_updateMain();
extern void dll_2E_func06(int* a, int* b, int c);
extern f32 sqrtf(f32 x);
extern void normalize(f32 * x, f32 * y, f32 * z);
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern int seqStreamLookupFn_8007fff8(void* table, int count, int key);
extern f32 Vec_xzDistance(void* a, void* b);
extern int randFn_80080100(int n);
extern void dll_2E_func04(void* sub, void* target);
extern void dll_2E_func0C(int a, void* p);
extern void buttonDisable(int port, u32 mask);
extern void characterDoEyeAnims(int* obj, void* p);
extern int gCfGuardianIdleMoveTable[]; /* per-quest-state idle move id (-1 = none) */
extern u8 lbl_803DBE20;     /* per-event sfx-id table passed to cfguardianPlayEventSfx */
extern f32 oneOverTimeDelta;

/* cfguardianPlayEventSfx: walk this step's triggered anim events and play the
 * matching per-event sfx. sfxIds is a 3-entry table: [0] the move sfx,
 * [1] the alt (event 7) sfx, [2] the "selection" sfx played once if any
 * 1..4 marker event fired. Returns the last 1..4 marker seen. */
int cfguardianPlayEventSfx(int obj, int evList, s16* sfxIds)
{
    int i;
    u8 marker;

    marker = 0;
    for (i = 0; i < ((ObjAnimEventList*)evList)->triggerCount; i++)
    {
        switch (*(s8*)(evList + i + offsetof(ObjAnimEventList, triggeredIds)))
        {
        case 0:
            if (sfxIds != NULL)
            {
                Sfx_PlayFromObject(obj, sfxIds[0]);
            }
            break;
        case 7:
            if (sfxIds != NULL)
            {
                Sfx_PlayFromObject(obj, sfxIds[1]);
            }
            break;
        case 1:
            marker = 1;
            break;
        case 2:
            marker = 2;
            break;
        case 3:
            marker = 3;
            break;
        case 4:
            marker = 4;
            break;
        case 9:
            Sfx_PlayFromObject(obj, GUARDIAN_SFX_FLAP);
            break;
        }
    }
    if (marker != 0 && sfxIds != NULL)
    {
        Sfx_PlayFromObject(obj, sfxIds[2]);
    }
    return marker;
}

/* cfguardian_setScale: true when the guardian is not mid path-flight
 * (queried by the render path to decide whether to apply scale). */
int cfguardian_setScale(int* obj)
{
    CfGuardianState* sub = ((GameObject*)obj)->extra;
    return (sub->flagsA9B & GUARDIAN_FLAG_PATH_FLYING) == 0;
}

/* cfguardianFlyAlongPath: fly the guardian along a rom-curve path. On the first
 * tick (unkF4 == 0) it steers to the nearest curve point then opens the
 * curve walker; thereafter it advances the walker, snaps the object to
 * the sampled position, sticks to the ground and blends the yaw toward
 * the heading of travel. Returns 1 once the path is exhausted. */
int cfguardianFlyAlongPath(int obj, int walker, f32 t, int pointId, int outPhase)
{
    int ret;
    int moved;
    u8 sel;
    int pt;
    s16 v;
    int cmd[2];
    RomCurveTarget tgt;
    f32 ground;

    moved = 1;
    ret = 0;
    ground = lbl_803E4110;
    if (((GameObject*)obj)->unkF4 == -1)
    {
        return 1;
    }
    if (((GameObject*)obj)->unkF4 == 0)
    {
        sel = pointId;
        pt = (int)findRomCurvePointNearObject((int*)obj, sel, 0, 2);
        tgt.x = ((RomCurvePlacementDef*)pt)->base.x;
        tgt.y = ((RomCurvePlacementDef*)pt)->base.y;
        tgt.z = ((RomCurvePlacementDef*)pt)->base.z;
        tgt.angle = ((RomCurvePlacementDef*)pt)->rotZ << 8;
        if (cfguardianSteerToward((int*)obj, (int*)&tgt.angle, t, outPhase) != 0)
        {
            cmd[0] = 0x19;
            cmd[1] = 0x15;
            (*gRomCurveInterface)->initCurve((void*)walker, (void*)obj, lbl_803E4120, cmd, sel);
            ((GameObject*)obj)->unkF4 = 1;
            moved = 1;
        }
    }
    else
    {
        ret = 0;
        if (Curve_AdvanceAlongPath(walker) != 0 || ((CfCurveWalker*)walker)->atEnd != 0)
        {
            ret = (*gRomCurveInterface)->goNextPoint((void*)walker);
        }
        ((GameObject*)obj)->anim.localPosX = ((CfCurveWalker*)walker)->posX;
        ((GameObject*)obj)->anim.localPosY = ((CfCurveWalker*)walker)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((CfCurveWalker*)walker)->posZ;
        if (ret != 0)
        {
            ((GameObject*)obj)->unkF4 = -1;
        }
        if (hitDetectFn_800658a4(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                 ((GameObject*)obj)->anim.localPosZ, &ground, 0) == 0)
        {
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - ground;
        }
    }
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)(obj, t, (float*)outPhase);
    if (moved != 0)
    {
        v = (s16)(getAngle(((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->anim.previousLocalPosX,
                           ((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->anim.previousLocalPosZ) + 0x8000);
        v = v - (u16)((GameObject*)obj)->anim.rotX;
        if (v > 0x8000)
        {
            v = v - 0xffff;
        }
        if (v < -0x8000)
        {
            v = v + 0xffff;
        }
        ((GameObject*)obj)->anim.rotX = *(s16*)(int)obj + (v >> 3);
    }
    if (((GameObject*)obj)->anim.currentMove != GUARDIAN_MOVE_FLY)
    {
        ObjAnim_SetCurrentMove(obj, GUARDIAN_MOVE_FLY, lbl_803E4110, 0);
    }
    return ret;
}

/* cfguardianSteerToward: steer the object toward the target: scale its velocity
 * along the normalized delta, blend the yaw by speed over distance,
 * move it and keep the chase move playing. Returns 1 when already
 * within the closing threshold. */
#pragma dont_inline on
int cfguardianSteerToward(int* obj, int* target, f32 speed, int outPhase)
{
    f32 dist;
    f32 dx;
    f32 dy;
    f32 dz;
    s16 d;
    if (target == NULL)
    {
        return 0;
    }
    dx = ((GameObject*)target)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
    dy = ((GameObject*)target)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
    dz = ((GameObject*)target)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
    dist = sqrtf(dz * dz + (dx * dx + dy * dy));
    if (dist < lbl_803E4124 * speed)
    {
        return 1;
    }
    normalize(&dx, &dy, &dz);
    ((GameObject*)obj)->anim.velocityX = timeDelta * (dx * speed);
    ((GameObject*)obj)->anim.velocityY = timeDelta * (dy * speed);
    ((GameObject*)obj)->anim.velocityZ = timeDelta * (dz * speed);
    d = (((GameObject*)target)->anim.rotX + 0x8000) - (u16)((GameObject*)obj)->anim.rotX;
    if (d > 0x8000)
    {
        d = d - 0xffff;
    }
    if (d < -0x8000)
    {
        d = d + 0xffff;
    }
    ((GameObject*)obj)->anim.rotX = (f32)*(s16*)(int)obj + ((lbl_803E4128 + d) * (speed * timeDelta)) / dist;
    objMove((int)obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
            ((GameObject*)obj)->anim.velocityZ);
    if (((GameObject*)obj)->anim.currentMove != GUARDIAN_MOVE_FLY)
    {
        ObjAnim_SetCurrentMove((int)obj, GUARDIAN_MOVE_FLY, lbl_803E4110, 0);
    }
    ((int(*)(int*, f32, int))ObjAnim_SampleRootCurvePhase)(obj, speed, outPhase);
    return 0;
}
#pragma dont_inline reset

#pragma dont_inline on
int* findRomCurvePointNearObject(int* obj, int curveGroup, int* outVec, int mode)
{
    int* result = NULL;
    int local[2];
    int found;

    if (mode == 1)
    {
        local[0] = 0;
        local[1] = 0;
    }
    else
    {
        local[0] = 25;
        local[1] = 21;
    }

    found = ((int (*)(f32, f32, f32, int*, int, int))(*gRomCurveInterface)->find)(
        ((GameObject*)obj)->anim.localPosX,
        ((GameObject*)obj)->anim.localPosY,
        ((GameObject*)obj)->anim.localPosZ,
        local, 2, curveGroup);

    if (found > -1)
    {
        result = (int*)(*gRomCurveInterface)->getById(found);
        if (outVec != NULL)
        {
            ((f32*)outVec)[0] = ((RomCurveDef*)result)->x;
            ((f32*)outVec)[1] = ((RomCurveDef*)result)->y;
            ((f32*)outVec)[2] = ((RomCurveDef*)result)->z;
        }
    }
    return result;
}
#pragma dont_inline reset

/* cfguardian_updateMain: the Queen's brain - the sixteen-state quest
 * progression (path flights, landing physics, dialogue triggers and idle
 * chatter) that runs from her caged release through to the spell-stone
 * see-off. */

static inline f32 cfguardianAbs(f32 x)
{
    if (x >= lbl_803E4110)
    {
        return x;
    }
    return -x;
}

int cfguardian_updateMain(int obj)
{
    CfGuardianState* sub;
    char* player;
    CfGuardianMapData* def;
    struct
    {
        f32 v[3];       /* scratch velocity delta during the landing bounce */
        u8 evbuf[0x1c]; /* ObjAnimEventList filled by ObjAnim_AdvanceCurrentMove */
    } stk;
    f32 k;
    f32 nearDist = lbl_803E412C;
    f32 ground = lbl_803E4130;
    def = (CfGuardianMapData*)((GameObject*)obj)->anim.placement;
    stk.evbuf[0x1b] = 0;
    sub = ((GameObject*)obj)->extra;
    sub->flagsA9B &= ~GUARDIAN_FLAG_PATH_FLYING;
    sub->moveSpeed = lbl_803E4134;
    player = Obj_GetPlayerObject();
    ObjTrigger_UpdateIdBlockFlag(obj);
    if (def->variant == 1 && GameBit_Get(GAMEBIT_GUARDIAN_CONVERGENCE) == 0)
    {
        ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        return 0;
    }
    ((GameObject*)obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    /* quest state machine: 0..3 the release, 4/6/7 the flight home,
       8..11 the talk spots, 12..15 the endgame cutscene parks */
    switch (sub->questState)
    {
    case CFGUARDIAN_DORMANT: /* dormant; wake once the quest starts (0x94f) */
        if (sub->chatterState == GUARDIAN_CHATTER_PLAYING)
        {
            sub->chatterState = GUARDIAN_CHATTER_READY;
        }
        if (GameBit_Get(GAMEBIT_GUARDIAN_QUEST_START) != 0)
        {
            sub->questState = CFGUARDIAN_CAGED;
        }
        break;
    case CFGUARDIAN_CAGED: /* wait for its own cage to open (0x4E - one of the four
               clouddungeon cage bits 0x4C-0x4F); alert + take off */
        if (sub->chatterState == GUARDIAN_CHATTER_PLAYING)
        {
            sub->chatterState = GUARDIAN_CHATTER_READY;
        }
        if (GameBit_Get(GAMEBIT_GUARDIAN_CAGE_OPEN) != 0)
        {
            sub->questState = CFGUARDIAN_RELEASE_SEQ;
            ObjAnim_SetCurrentMove(obj, GUARDIAN_MOVE_FLY, lbl_803E4110, 0);
            ((GameObject*)obj)->unkF4 = 0;
            GameBit_Set(GAMEBIT_GUARDIAN_PRISONGUARD_STAND_DOWN, 1);
            sub->flagsA9B |= GUARDIAN_FLAG_MOVE_LATCHED;
        }
        break;
    case CFGUARDIAN_FLY_ESCAPE: /* fly the escape curve; roost at the end */
        if (sub->chatterState == GUARDIAN_CHATTER_PLAYING)
        {
            sub->chatterState = GUARDIAN_CHATTER_READY;
        }
        sub->flagsA9B |= GUARDIAN_FLAG_PATH_FLYING;
        if (((CfFlyAlongPathFn)cfguardianFlyAlongPath)((int*)obj, sub->pathBlock, lbl_803E4138, 0, &sub->moveSpeed) != 0)
        {
            sub->flagsA9B &= ~GUARDIAN_FLAG_MOVE_LATCHED;
            sub->questState = CFGUARDIAN_ROOST;
        }
        break;
    case CFGUARDIAN_RELEASE_SEQ: /* play the release sequence once */
        (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
        GameBit_Set(GAMEBIT_GUARDIAN_RELEASED, 1);
        sub->questState = CFGUARDIAN_FLY_ESCAPE;
        break;
    case CFGUARDIAN_ROOST: /* roost until the convergence cutscene parks her */
        if (GameBit_Get(GAMEBIT_GUARDIAN_CONVERGENCE) != 0)
        {
            if (def->variant != 1)
            {
                sub->questState = CFGUARDIAN_PARKED_HIDDEN;
                sub->chatterAlt = 0;
            }
            else
            {
                sub->questState = CFGUARDIAN_PARKED;
                sub->chatterAlt = 0;
            }
        }
        else if (sub->chatterState == GUARDIAN_CHATTER_PLAYING)
        {
            sub->chatterState = GUARDIAN_CHATTER_READY;
            sub->chatterAlt = (s8)((sub->chatterAlt + 1) % 2);
        }
        break;
    case CFGUARDIAN_LANDING: /* free-fall to the ground, then settle at the curve home */
        if (sub->landingPhase != 0)
        {
            if (sub->landingPhase >= 2)
            {
                {
                    f32 fz = lbl_803E4110;
                    ((GameObject*)obj)->anim.velocityX = fz;
                    ((GameObject*)obj)->anim.velocityZ = fz;
                }
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)
                    ->anim.localPosY;
                hitDetectFn_800658a4(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                     ((GameObject*)obj)->anim.localPosZ, &ground, 0);
                ((GameObject*)obj)->anim.rotX = (s16)((0xc0 << (((GameObject*)obj)->anim.rotX + 8)) >> 1);
                ObjAnim_GetPriorityHitState(&((GameObject*)obj)->anim)->flags &= ~0x400;
                if (ground <= lbl_803E4130)
                {
                    sub->landingPhase = 2;
                    ((GameObject*)obj)->anim.localPosY -= ground;
                    sub->chatterState = GUARDIAN_CHATTER_READY;
                    ((GameObject*)obj)->unkF4 = 0;
                    ObjAnim_SetCurrentMove(obj, 0, lbl_803E4110, 0);
                    {
                        RomCurvePlacementDef* pt = (RomCurvePlacementDef*)findRomCurvePointNearObject((int*)obj, 0, 0, 2);
                        f32 d;
                        sub->homeX = pt->base.x;
                        sub->homeY = pt->base.y;
                        sub->homeZ = pt->base.z;
                        sub->homeYaw = (s16)(pt->rotZ << 8);
                        d = sub->homeY - ((GameObject*)obj)->anim.localPosY;
                        d = (d >= lbl_803E4110) ? d : -d;
                        if (d < lbl_803E413C)
                        {
                            ObjGroup_AddObject(obj, CFGUARDIAN_OBJGROUP);
                            sub->questState = CFGUARDIAN_FLY_TO_TALK;
                            ObjAnim_SetCurrentMove(obj, GUARDIAN_MOVE_FLY, lbl_803E4110, 0);
                        }
                    }
                }
                else
                {
                    ((GameObject*)obj)->anim.velocityY -= lbl_803E4140;
                }
            }
            else
            {
                f32 w = cfguardianAbs(lbl_803E4144 * ((GameObject*)obj)->anim.velocityY);
                f32 r;
                r = (f32)((GameObject*)obj)->anim.rotX;
                r = r + w;
                ((GameObject*)obj)->anim.rotX = r;
                sub->moveSpeed = lbl_803E4148;
                if (GameBit_Get(GAMEBIT_GUARDIAN_LANDED) != 0)
                {
                    ObjAnim_SetCurrentMove(obj, 0, lbl_803E4110, 0);
                    ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x32);
                    ((GameObject*)obj)->anim.velocityY = lbl_803E4110;
                    ObjGroup_RemoveObject(obj, CFGUARDIAN_OBJGROUP);
                    {
                        f32 fz = lbl_803E4110;
                        ((GameObject*)obj)->anim.velocityX = fz;
                        ((GameObject*)obj)->anim.velocityY = lbl_803E414C;
                        ((GameObject*)obj)->anim.velocityZ = fz;
                    }
                    sub->landingPhase = 2;
                    sub->flagsA9B &= ~GUARDIAN_FLAG_MOVE_LATCHED;
                }
            }
            if (sub->landingPhase < 2)
            {
                ((GameObject*)obj)->anim.localPosX = timeDelta * ((GameObject*)obj)->anim.velocityX + ((GameObject*)obj)
                    ->anim.localPosX;
                ((GameObject*)obj)->anim.localPosZ = timeDelta * ((GameObject*)obj)->anim.velocityZ + ((GameObject*)obj)
                    ->anim.localPosZ;
                if (sub->bounceLatch != 0)
                {
                {
                    f32 fb = lbl_803E4150;
                    ((GameObject*)obj)->anim.velocityX = fb * -((GameObject*)obj)->anim.velocityX;
                    ((GameObject*)obj)->anim.velocityZ = fb * -((GameObject*)obj)->anim.velocityZ;
                }
                }
                {
                    f32 v1;
                    f32 v0;
                    f32 v2;
                    f32 v3;
                    v0 = ((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->anim.previousLocalPosX;
                    stk.v[0] = v0;
                    v1 = ((GameObject*)obj)->anim.localPosY - ((GameObject*)obj)->anim.previousLocalPosY;
                    stk.v[1] = v1;
                    v2 = ((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->anim.previousLocalPosZ;
                    stk.v[2] = v2;
                    k = lbl_803E4154 * oneOverTimeDelta;
                    v0 = v0 * k;
                    stk.v[0] = v0;
                    v1 = v1 * k;
                    stk.v[1] = v1;
                    v3 = v2 * k;
                    stk.v[2] = v3;
                    ((GameObject*)obj)->anim.velocityX = v0 + ((GameObject*)obj)->anim.velocityX;
                    ((GameObject*)obj)->anim.velocityY = v1 + ((GameObject*)obj)->anim.velocityY;
                    ((GameObject*)obj)->anim.velocityZ = v3 + ((GameObject*)obj)->anim.velocityZ;
                }
                {
                    f32 fd = lbl_803E4138;
                    ((GameObject*)obj)->anim.velocityX = fd * ((GameObject*)obj)->anim.velocityX;
                    ((GameObject*)obj)->anim.velocityY = fd * ((GameObject*)obj)->anim.velocityY;
                    ((GameObject*)obj)->anim.velocityZ = fd * ((GameObject*)obj)->anim.velocityZ;
                }
            }
        }
        else
        {
            if (sub->chatterState == GUARDIAN_CHATTER_PLAYING)
            {
                sub->chatterState = GUARDIAN_CHATTER_READY;
            }
        }
        break;
    case CFGUARDIAN_FLY_TO_TALK: /* fly to the talk spot */
        if (sub->chatterState == GUARDIAN_CHATTER_PLAYING)
        {
            sub->chatterState = GUARDIAN_CHATTER_READY;
        }
        sub->flagsA9B |= GUARDIAN_FLAG_PATH_FLYING;
        if (((CfFlyAlongPathFn)cfguardianFlyAlongPath)((int*)obj, sub->pathBlock, lbl_803E4138, 1, &sub->moveSpeed) != 0)
        {
            sub->questState = CFGUARDIAN_TALK_1;
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x32);
        }
        break;
    case CFGUARDIAN_TALK_1: /* talk spot: greet and head-track the player; 0x43 advances */
        {
            void* found = (void*)ObjGroup_FindNearestObject(3, obj, &nearDist);
            if (found != NULL && nearDist < lbl_803E4158)
            {
                dll_2E_func04(sub, found);
                ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
            }
        }
        if (nearDist > lbl_803E4158 && Vec_xzDistance(player + offsetof(GameObject, anim.worldPosX), (char*)obj + offsetof(GameObject, anim.worldPosX)) < lbl_803E413C)
        {
            ((GameObject*)obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
            if ((sub->flagsA9B & GUARDIAN_FLAG_HOMING) == 0 && gCfGuardianIdleMoveTable[sub->questState] != 0)
            {
                dll_2E_func0C(0xf, &sub->homeYaw);
                sub->flagsA9B |= GUARDIAN_FLAG_MOVE_LATCHED | GUARDIAN_FLAG_HOMING;
                gCfGuardianIdleMoveTable[sub->questState] = 0;
            }
            if (sub->chatterState == GUARDIAN_CHATTER_PLAYING)
            {
                sub->chatterState = GUARDIAN_CHATTER_READY;
                sub->chatterAlt = (s8)((sub->chatterAlt + 1) % 2);
            }
        }
        else
        {
            if ((sub->flagsA9B & GUARDIAN_FLAG_HOMING) == 0 && gCfGuardianIdleMoveTable[sub->questState] != 0xe)
            {
                sub->chatterState = GUARDIAN_CHATTER_PLAYING;
                sub->flagsA9B |= GUARDIAN_FLAG_MOVE_LATCHED | GUARDIAN_FLAG_HOMING;
                dll_2E_func0A(0xe, (int*)&sub->homeYaw);
                gCfGuardianIdleMoveTable[sub->questState] = 0xe;
            }
        }
        if ((sub->flagsA9B & GUARDIAN_FLAG_HOMING) != 0
            && cfguardianSteerToward((int*)obj, (int*)&sub->homeYaw, lbl_803E4128, (int)&sub->moveSpeed) != 0)
        {
            ObjAnim_SetCurrentMove(obj, GUARDIAN_MOVE_FLY, lbl_803E4110, 0);
            sub->flagsA9B &= ~(GUARDIAN_FLAG_MOVE_LATCHED | GUARDIAN_FLAG_HOMING);
        }
        if (GameBit_Get(0x43) != 0)
        {
            sub->questState = CFGUARDIAN_TALK_2;
            sub->chatterAlt = 0;
        }
        break;
    case CFGUARDIAN_TALK_2: /* second talk loop; 0x4be sends her onward */
        {
            void* found = (void*)ObjGroup_FindNearestObject(3, obj, &nearDist);
            if (found != NULL && nearDist < lbl_803E4158)
            {
                dll_2E_func04(sub, found);
            }
        }
        if (nearDist > lbl_803E4158 && Vec_xzDistance(player + offsetof(GameObject, anim.worldPosX), (char*)obj + offsetof(GameObject, anim.worldPosX)) < lbl_803E413C)
        {
            if ((sub->flagsA9B & GUARDIAN_FLAG_HOMING) == 0 && gCfGuardianIdleMoveTable[sub->questState] != 0)
            {
                dll_2E_func0C(0xf, &sub->homeYaw);
                sub->flagsA9B |= GUARDIAN_FLAG_MOVE_LATCHED | GUARDIAN_FLAG_HOMING;
                gCfGuardianIdleMoveTable[sub->questState] = 0;
            }
            if (sub->chatterState == GUARDIAN_CHATTER_PLAYING)
            {
                sub->chatterState = GUARDIAN_CHATTER_READY;
                sub->chatterAlt = (s8)((sub->chatterAlt + 1) % 2);
            }
        }
        else
        {
            if ((sub->flagsA9B & GUARDIAN_FLAG_HOMING) == 0 && gCfGuardianIdleMoveTable[sub->questState] != 0xe)
            {
                sub->chatterState = GUARDIAN_CHATTER_PLAYING;
                sub->flagsA9B |= GUARDIAN_FLAG_MOVE_LATCHED | GUARDIAN_FLAG_HOMING;
                dll_2E_func0A(0xe, (int*)&sub->homeYaw);
                gCfGuardianIdleMoveTable[sub->questState] = 0xe;
            }
        }
        if ((sub->flagsA9B & GUARDIAN_FLAG_HOMING) != 0
            && cfguardianSteerToward((int*)obj, (int*)&sub->homeYaw, lbl_803E4128, (int)&sub->moveSpeed) != 0)
        {
            ObjAnim_SetCurrentMove(obj, GUARDIAN_MOVE_FLY, lbl_803E4110, 0);
            sub->flagsA9B &= ~(GUARDIAN_FLAG_MOVE_LATCHED | GUARDIAN_FLAG_HOMING);
        }
        if (GameBit_Get(0x4be) != 0)
        {
            sub->questState = CFGUARDIAN_FLY_OUT;
            ObjAnim_SetCurrentMove(obj, GUARDIAN_MOVE_FLY, lbl_803E4110, 0);
            ((GameObject*)obj)->unkF4 = 0;
        }
        break;
    case CFGUARDIAN_FLY_OUT: /* final flight out */
        if (sub->chatterState == GUARDIAN_CHATTER_PLAYING)
        {
            sub->chatterState = GUARDIAN_CHATTER_READY;
        }
        sub->flagsA9B |= GUARDIAN_FLAG_PATH_FLYING;
        if (((CfFlyAlongPathFn)cfguardianFlyAlongPath)((int*)obj, sub->pathBlock, lbl_803E415C, 2, &sub->moveSpeed) != 0)
        {
            sub->questState = CFGUARDIAN_VANISH;
        }
        break;
    case CFGUARDIAN_VANISH: /* vanish: fade out and stop updating */
        if (sub->chatterState == GUARDIAN_CHATTER_PLAYING)
        {
            sub->chatterState = GUARDIAN_CHATTER_READY;
        }
        ((GameObject*)obj)->anim.alpha = 0;
        ObjAnim_GetPriorityHitState(&((GameObject*)obj)->anim)->flags &= ~1;
        Obj_RemoveFromUpdateList((int*)obj);
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        sub->questState = CFGUARDIAN_PARKED_HIDDEN;
        break;
    case CFGUARDIAN_CUTSCENE_PERCH_A: /* cutscene perch: sequence 0xB on demand (0x4b7) */
        if (sub->chatterState == GUARDIAN_CHATTER_PLAYING)
        {
            sub->chatterState = GUARDIAN_CHATTER_READY;
        }
        if (GameBit_Get(0x4b7) != 0)
        {
            (*gCameraInterface)->setTarget(obj);
            (*gObjectTriggerInterface)->runSequence(0xb, (void*)obj, -1);
            GameBit_Set(0x4b7, 0);
        }
        if (GameBit_Get(0x49a) != 0)
        {
            sub->questState = CFGUARDIAN_CUTSCENE_PERCH_B;
        }
        break;
    case CFGUARDIAN_CUTSCENE_PERCH_B: /* cutscene perch: sequence 0xA on demand (0x4b7) */
        if (sub->chatterState == GUARDIAN_CHATTER_PLAYING)
        {
            sub->chatterState = GUARDIAN_CHATTER_READY;
        }
        if (GameBit_Get(0x4b7) != 0)
        {
            (*gCameraInterface)->setTarget(obj);
            (*gObjectTriggerInterface)->runSequence(0xa, (void*)obj, -1);
            GameBit_Set(0x4b7, 0);
        }
        if (GameBit_Get(0x4aa) != 0)
        {
            sub->questState = CFGUARDIAN_PARKED;
        }
        break;
    case CFGUARDIAN_PARKED: /* parked, idle chatter only */
        if (sub->chatterState == GUARDIAN_CHATTER_PLAYING)
        {
            sub->chatterState = GUARDIAN_CHATTER_READY;
        }
        break;
    case CFGUARDIAN_PARKED_HIDDEN: /* parked and hidden */
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        Obj_RemoveFromUpdateList((int*)obj);
        ObjAnim_GetPriorityHitState(&((GameObject*)obj)->anim)->flags &= ~1;
        break;
    }
    dll_2E_func03(obj, sub);
    if (ObjTrigger_IsSet(obj) != 0)
    {
        buttonDisable(0, PAD_BUTTON_A);
        if ((*gGameUIInterface)->isEventReady(0x2e8) != 0)
        {
            GameBit_Set(0x4ab, 1);
        }
        else if (sub->chatterState == GUARDIAN_CHATTER_READY)
        {
            int* tbl = (int*)seqStreamLookupFn_8007fff8(gCfGuardianSeqStreamTable, 0xf, sub->questState);
            int pick;
            if (Player_GetCurrentMagic((int)player) > 3)
            {
                pick = tbl[0];
            }
            else
            {
                pick = tbl[1];
            }
            if (sub->chatterPick % 2 != 0 && tbl[2] != -1)
            {
                pick = tbl[2];
            }
            sub->chatterPick += 1;
            if (pick != -1)
            {
                sub->chatterState = GUARDIAN_CHATTER_PLAYING;
                (*gObjectTriggerInterface)->runSequence(pick, (void*)obj, -1);
            }
        }
    }
    if (GameBit_Get(0x902) != 0)
    {
        int* tbl2 = (int*)seqStreamLookupFn_8007fff8(gCfGuardianSeqStreamTable, 0xf, sub->questState);
        if (tbl2[0] != -1)
        {
            sub->chatterState = GUARDIAN_CHATTER_PLAYING;
            (*gObjectTriggerInterface)->runSequence(tbl2[0], (void*)obj, -1);
            GameBit_Set(0x902, 0);
        }
    }
    {
        int mv = gCfGuardianIdleMoveTable[sub->questState];
        if (mv != -1 && (sub->flagsA9B & GUARDIAN_FLAG_MOVE_LATCHED) == 0 && ((GameObject*)obj)->anim.currentMove != mv)
        {
            ObjAnim_SetCurrentMove(obj, mv, lbl_803E4110, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x50);
        }
    }
    if (((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, sub->moveSpeed, framesThisStep,
                                                                    stk.evbuf) != 0
        && (sub->flagsA9B & GUARDIAN_FLAG_MOVE_LATCHED) != 0
        && ((GameObject*)obj)->anim.currentMove != GUARDIAN_MOVE_FLY
        && ((GameObject*)obj)->anim.currentMove != 9)
    {
        sub->flagsA9B &= ~GUARDIAN_FLAG_MOVE_LATCHED;
    }
    ((CfPlayEventSfxFn)cfguardianPlayEventSfx)((int*)obj, (u8*)&stk + 12, &lbl_803DBE20);
    if (randFn_80080100(0x3c) != 0)
    {
        objAudioFn_800393f8(obj, sub->audioBlock, GUARDIAN_SFX_CHATTER, 0x1000, -1, 0);
    }
    objAnimFn_80038f38(obj, sub->audioBlock);
    characterDoEyeAnims((int*)obj, sub->eyeBlock);
    if (sub->questState != GameBit_Get(GAMEBIT_GUARDIAN_QUEST_STATE))
    {
        GameBit_Set(GAMEBIT_GUARDIAN_QUEST_STATE, sub->questState);
    }
    return 0;
}

/* cfguardian_SeqFn: the Queen's sequence message handler.
 * Persists position on a negative cue, otherwise picks the active/idle
 * heading pair and routes a move request; on the magic-grant cue
 * (triggerCommand 2) it refills the player's magic. Returns 1 if the move
 * was consumed. */
int cfguardian_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int* sel;
    GuardianMsg stk;
    CfGuardianState* sub = ((GameObject*)obj)->extra;
    stk = gCfGuardianHeadingTemplate;
    if (((GameObject*)obj)->seqIndex < 0)
    {
        saveGame_saveObjectPos((int)obj);
        return 0;
    }
    if (sub->questState != CFGUARDIAN_LANDING)
    {
        sel = &stk.a;
    }
    else
    {
        sel = &stk.c;
    }
    if (animatedObjGetSeqId((int*)animUpdate) != 0x283)
    {
        if (dll_2E_func07((int)obj, (ObjSeqState*)animUpdate, (char*)sub, sel[0], sel[1]) != 0)
        {
            return 1;
        }
    }
    if (animUpdate->triggerCommand == 2)
    {
        playerAddRemoveMagic(Obj_GetPlayerObject(), 0xa);
    }
    return 0;
}

int cfguardian_getExtraSize(void) { return 0xa9c; }

int cfguardian_getObjectTypeId(void) { return 0x41; }

void cfguardian_free(int* obj, int keep)
{
    char* extra = ((GameObject*)obj)->extra;
    if (keep == 0)
    {
        char* state;
        int i;
        for (i = 0, state = extra; i < 6; i++)
        {
            int* linked = (int*)((CfGuardianState*)state)->linkedObjs[0];
            if (linked != NULL)
            {
                Obj_FreeObject(linked);
            }
            state += 4;
        }
    }
}

void cfguardian_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int* sub = ((GameObject*)obj)->extra;
    if ((s32)visible != 0)
    {
        objRenderFn_8003b8f4(lbl_803E4130);
        dll_2E_func06(obj, sub, 0);
    }
}

void cfguardian_hitDetect(int* obj)
{
    ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.localPosZ;
}

void cfguardian_update(int obj) { cfguardian_updateMain(obj); }

void cfguardian_init(int* obj, u8* params)
{
    CfGuardianState* sub;
    GuardianVec stk1;
    GuardianVec stk2;

    sub = ((GameObject*)obj)->extra;
    stk1 = gCfGuardianHitboxTemplateA;
    stk2 = gCfGuardianHitboxTemplateB;
    if (sub == NULL) return;
    ObjMsg_AllocQueue(obj, 4);
    sub->questState = GameBit_Get(GAMEBIT_GUARDIAN_QUEST_STATE);
    ((GameObject*)obj)->unkF4 = 1;
    ((GameObject*)obj)->animEventCallback = cfguardian_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)(((CfGuardianMapData*)params)->rotXByte << 8);
    sub->landingPhase = 0;
    sub->moveSpeed = lbl_803E4110;
    sub->unkA90 = 6;
    sub->flagsA9B = 0;
    sub->flags611 = (u8)(sub->flags611 | 0x28);
    sub->chatterState = GUARDIAN_CHATTER_READY;
    sub->chatterAlt = 0;
    sub->chatterPick = 0;
    if (GameBit_Get(GAMEBIT_GUARDIAN_CONVERGENCE) != 0)
    {
        sub->questState = CFGUARDIAN_ROOST;
        if (((CfGuardianMapData*)params)->variant == 0)
        {
            ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
            Obj_RemoveFromUpdateList(obj);
        }
    }
    else if (GameBit_Get(GAMEBIT_GUARDIAN_RELEASED) != 0 && ((CfGuardianMapData*)params)->variant == 0)
    {
        sub->questState = CFGUARDIAN_ROOST;
        dll_2E_func0A(8, obj);
    }
    ObjHits_EnableObject(obj);
    dll_2E_func05(obj, (u8*)sub, -0x2000, 0x2800, 4);
    dll_2E_func08((u8*)sub, 0x12c, 0x64);
    dll_2E_func09((u8*)sub, &stk2, &stk1, 4);
    objSeqInitFn_80080078(gCfGuardianSeqStreamTable, 0xf);
    sub->flags611 = (u8)(sub->flags611 | 0x2);
}

void cfguardian_release(void)
{
}

void cfguardian_initialise(void)
{
}

extern u8 lbl_80322798[];
extern u8 lbl_803227A4[];
extern u8 lbl_803227B0[];
extern u8 lbl_803227BC[];
extern u8 lbl_803227C8[];
extern u8 lbl_803227D4[];
extern u8 lbl_803227E0[];
extern u8 lbl_803227EC[];
extern u8 lbl_803227F8[];
extern u8 lbl_80322804[];
extern u8 lbl_80322810[];
extern u8 lbl_8032281C[];
extern u8 lbl_80322828[];
extern u8 lbl_80322834[];
extern u8 lbl_80322840[];

int gCfGuardianSeqStreamTable[33][2] = {
    { 0, (int)&lbl_80322798 },
    { 1, (int)&lbl_803227A4 },
    { 2, (int)&lbl_803227B0 },
    { 3, (int)&lbl_803227BC },
    { 4, (int)&lbl_803227C8 },
    { 5, (int)&lbl_803227D4 },
    { 6, (int)&lbl_803227E0 },
    { 7, (int)&lbl_803227EC },
    { 8, (int)&lbl_803227F8 },
    { 9, (int)&lbl_80322804 },
    { 10, (int)&lbl_80322810 },
    { 12, (int)&lbl_8032281C },
    { 13, (int)&lbl_80322828 },
    { 14, (int)&lbl_80322834 },
    { 15, (int)&lbl_80322840 },
    { 0, 8 },
    { 1, 8 },
    { 2, 8 },
    { 3, 10 },
    { 4, 10 },
    { 5, 10 },
    { 6, 11 },
    { 7, 11 },
    { 8, 12 },
    { 9, 12 },
    { 10, -1 },
    { 12, -1 },
    { 13, -1 },
    { 14, -1 },
    { 15, -1 },
    { 0, 0 },
    { 0, 18 },
    { 14, 10 },
};

int gCfGuardianIdleMoveTable[20] = {
    -1, 0, 26, 0, 0, -1, -1, 26, 14, 14, 26, 26, 0, 0, -1, 10, 11, 12, 13, 14
};

ObjectDescriptor11 gCFGuardianObjDescriptor = {
    0,
    0,
    0,
    0xA0000,
    (ObjectDescriptorCallback)cfguardian_initialise,
    (ObjectDescriptorCallback)cfguardian_release,
    0,
    (ObjectDescriptorCallback)cfguardian_init,
    (ObjectDescriptorCallback)cfguardian_update,
    (ObjectDescriptorCallback)cfguardian_hitDetect,
    (ObjectDescriptorCallback)cfguardian_render,
    (ObjectDescriptorCallback)cfguardian_free,
    (ObjectDescriptorCallback)cfguardian_getObjectTypeId,
    (ObjectDescriptorCallback)cfguardian_getExtraSize,
    (ObjectDescriptorCallback)cfguardian_setScale,
};
