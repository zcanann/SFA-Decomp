/*
 * cfguardian (DLL 0x148) - the CloudRunner Fortress guardian. The big
 * cfguardian_updateMain drives the quest state machine (chatter, curve
 * flight between rom-curve points, the six fire spirits and the water
 * spell stone hand-off); helpers steer along rom curves (fn_8019B1D8)
 * and play per-event sfx (fn_8019AE3C). Carved from the front of the
 * sandwormBoss container; the 0x148 TU truly starts in DR/hightop.c
 * (documented cut in docs/boundary_audit.md).
 */

#include "main/game_object.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_0015_curves.h"
#include "main/obj_placement.h"
#include "main/dll/cfguardian_state.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/objseq.h"

typedef struct
{
    s16 angle;
    s16 pad[5];
    f32 x;
    f32 y;
    f32 z;
} RomCurveTarget;

typedef struct
{
    s16 v[5];
} GuardianVec;

typedef struct
{
    int a, b, c, d;
} GuardianMsg;

typedef struct CfGuardianMapData
{
    ObjPlacement base;
    s8 unk18;
    s8 variant; /* 0x19: 1 = the convergence-gated guardian */
} CfGuardianMapData;

STATIC_ASSERT(sizeof(CfGuardianState) == 0xa9c);
STATIC_ASSERT(offsetof(CfGuardianMapData, variant) == 0x19);

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int* findRomCurvePointNearObject(int* obj, int p2, int* outVec, int p4);
extern int fn_8019B1D8(int* obj, int* target, f32 speed, int p4);
extern int Curve_AdvanceAlongPath(int p1);
extern s16 getAngle(f32 a, f32 b);
extern f32 lbl_803E4110;
extern f32 lbl_803E4120;
extern int ObjHits_EnableObject();
extern int ObjGroup_FindNearestObject();
extern int ObjGroup_RemoveObject();
extern int ObjGroup_AddObject();
extern int ObjMsg_AllocQueue();
extern bool ObjTrigger_UpdateIdBlockFlag(int obj);
extern int ObjTrigger_IsSet();
extern int objAnimFn_80038f38();
extern void objRenderFn_8003b8f4(f32);
extern int dll_2E_func03();
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern uint GameBit_Get(int eventId);
extern int Obj_RemoveFromUpdateList(int* obj);
extern GuardianVec lbl_802C22C0;
extern GuardianVec lbl_802C22CC;
extern u8 lbl_8032284C[];
extern void dll_2E_func0A(int a, int* obj);
extern void dll_2E_func05(int* obj, u8* sub, int c, int d, int e);
extern void dll_2E_func08(u8* sub, int b, int c);
extern void dll_2E_func09(u8* sub, void* a, void* b, int c);
extern void objSeqInitFn_80080078(u8* p, int n);
extern GuardianMsg lbl_802C22D8;
extern int dll_2E_func07(int* obj, ObjAnimUpdateState* animUpdate, u8* sub, int x, int y);
extern int animatedObjGetSeqId(int* p);
extern void saveGame_saveObjectPos(int obj);
extern void* Obj_GetPlayerObject(void);
extern void playerAddRemoveMagic(void* player, int n);
extern void fn_8003ADC4(int* a, int* b, void* c, int d, int e, int f);
extern f32 timeDelta;
extern void objAudioFn_800393f8(int obj, void* p, int a, int b, int c, int d);
extern u8 framesThisStep;
extern int cfguardian_updateMain();
extern f32 lbl_803E4130;
extern void dll_2E_func06(int* a, int* b, int c);
extern f32 sqrtf(f32 x);
extern void normalize(f32 * x, f32 * y, f32 * z);
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern f32 lbl_803E4124;
extern f32 lbl_803E4128;
extern int seqStreamLookupFn_8007fff8(void* table, int count, int key);
extern f32 Vec_xzDistance(void* a, void* b);
extern int randFn_80080100(int n);
extern int fn_80296A14(int p);
extern void dll_2E_func04(void* sub, void* target);
extern void dll_2E_func0C(int a, void* p);
extern void buttonDisable(int a, int b);
extern void characterDoEyeAnims(int* obj, void* p);
extern int lbl_80322954[];
extern u8 lbl_803DBE20;
extern f32 oneOverTimeDelta;
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
extern f32 lbl_803E412C;

int fn_8019AE3C(int p1, int p2, s16* p3)
{
    extern void Sfx_PlayFromObject(int, u16); /* #57/#115 */
    int i;
    u8 v;

    v = 0;
    for (i = 0; i < *(s8*)(p2 + 0x1b); i++)
    {
        switch (*(s8*)(p2 + i + 0x13))
        {
        case 0:
            if (p3 != NULL)
            {
                Sfx_PlayFromObject(p1, (u16)p3[0]);
            }
            break;
        case 7:
            if (p3 != NULL)
            {
                Sfx_PlayFromObject(p1, (u16)p3[1]);
            }
            break;
        case 1:
            v = 1;
            break;
        case 2:
            v = 2;
            break;
        case 3:
            v = 3;
            break;
        case 4:
            v = 4;
            break;
        case 9:
            Sfx_PlayFromObject(p1, 0xe1);
            break;
        }
    }
    if (v != 0 && p3 != NULL)
    {
        Sfx_PlayFromObject(p1, (u16)p3[2]);
    }
    return v;
}

int cfguardian_setScale(int* obj)
{
    return (*(u8*)(*(int*)&((GameObject*)obj)->extra + 0xa9b) & 0x2) == 0;
}

int fn_8019AF64(int obj, int p2, f32 t, int p3, int p4)
{
    extern int hitDetectFn_800658a4(int obj, f32 x, f32 y, f32 z, f32* out, int p6); /* #57/#29 */
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
        sel = p3;
        pt = (int)findRomCurvePointNearObject((int*)obj, sel, 0, 2);
        tgt.x = ((RomCurvePlacementDef*)pt)->base.x;
        tgt.y = ((RomCurvePlacementDef*)pt)->base.y;
        tgt.z = ((RomCurvePlacementDef*)pt)->base.z;
        tgt.angle = ((RomCurvePlacementDef*)pt)->rotZ << 8;
        if (fn_8019B1D8((int*)obj, (int*)&tgt.angle, t, p4) != 0)
        {
            cmd[0] = 0x19;
            cmd[1] = 0x15;
            (*gRomCurveInterface)->initCurve((void*)p2, (void*)obj, lbl_803E4120, cmd, sel);
            ((GameObject*)obj)->unkF4 = 1;
            moved = 1;
        }
    }
    else
    {
        ret = 0;
        if (Curve_AdvanceAlongPath(p2) != 0 || *(int*)(p2 + 0x10) != 0)
        {
            ret = (*gRomCurveInterface)->goNextPoint((void*)p2);
        }
        ((GameObject*)obj)->anim.localPosX = *(f32*)(p2 + 0x68);
        ((GameObject*)obj)->anim.localPosY = *(f32*)(p2 + 0x6c);
        ((GameObject*)obj)->anim.localPosZ = *(f32*)(p2 + 0x70);
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
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)(obj, t, (float*)p4);
    if (moved != 0)
    {
        v = (s16)(getAngle(((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->anim.previousLocalPosX,
                           ((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->anim.previousLocalPosZ) + 0x8000);
        v = v - (u16)*(s16*)obj;
        if (v > 0x8000)
        {
            v = v - 0xffff;
        }
        if (v < -0x8000)
        {
            v = v + 0xffff;
        }
        *(s16*)obj = *(s16*)(int)obj + (v >> 3);
    }
    if (((GameObject*)obj)->anim.currentMove != 0x1a)
    {
        ObjAnim_SetCurrentMove(obj, 0x1a, lbl_803E4110, 0);
    }
    return ret;
}

/* fn_8019B1D8: steer the object toward the target: scale its velocity
 * along the normalized delta, blend the yaw by speed over distance,
 * move it and keep the chase move playing. Returns 1 when already
 * within the closing threshold. */
#pragma dont_inline on
int fn_8019B1D8(int* obj, int* target, f32 speed, int p4)
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
    d = (*(s16*)target + 0x8000) - (u16)*(s16*)obj;
    if (d > 0x8000)
    {
        d = d - 0xffff;
    }
    if (d < -0x8000)
    {
        d = d + 0xffff;
    }
    *(s16*)obj = (f32)*(s16*)(int)obj + ((lbl_803E4128 + (f32)d) * (speed * timeDelta)) / dist;
    objMove((int)obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
            ((GameObject*)obj)->anim.velocityZ);
    if (((GameObject*)obj)->anim.currentMove != 0x1a)
    {
        ObjAnim_SetCurrentMove((int)obj, 0x1a, lbl_803E4110, 0);
    }
    ((int(*)(int*, f32, int))ObjAnim_SampleRootCurvePhase)(obj, speed, p4);
    return 0;
}
#pragma dont_inline reset

#pragma dont_inline on
int* findRomCurvePointNearObject(int* obj, int p2, int* outVec, int p4)
{
    int* result = NULL;
    int local[2];
    int found;

    if (p4 == 1)
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
        local, 2, p2);

    if (found > -1)
    {
        result = (int*)(*gRomCurveInterface)->getById(found);
        if (outVec != NULL)
        {
            *(f32*)((char*)outVec + 0) = *(f32*)((char*)result + 8);
            *(f32*)((char*)outVec + 4) = *(f32*)((char*)result + 12);
            *(f32*)((char*)outVec + 8) = *(f32*)((char*)result + 16);
        }
    }
    return result;
}
#pragma dont_inline reset

/* cfguardian_updateMain: the guardian brain - sixteen-state
 * quest progression with path flights, landing physics, sequenced
 * triggers and idle chatter. */

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
    extern int hitDetectFn_800658a4(int* obj, f32 x, f32 y, f32 z, f32* out, int p); /* #57 */
    extern void fn_8019AE3C(int* obj, void* evbuf, void* p); /* #57 */
    extern int fn_8019AF64(int* obj, void* path, f32 f, int phase, void* spd); /* #57 */
    CfGuardianState* sub;
    char* player;
    u8* def;
    struct
    {
        f32 v[3];
        u8 evbuf[0x1c];
    } stk;
    f32 k;
    f32 nearDist = lbl_803E412C;
    f32 ground = lbl_803E4130;
    def = (u8*)((GameObject*)obj)->anim.placement;
    stk.evbuf[0x1b] = 0;
    sub = ((GameObject*)obj)->extra;
    sub->flagsA9B &= ~0x2;
    sub->moveSpeed = lbl_803E4134;
    player = (char*)Obj_GetPlayerObject();
    ObjTrigger_UpdateIdBlockFlag(obj);
    if (((CfGuardianMapData*)def)->variant == 1 && GameBit_Get(0x57) == 0)
    {
        ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        return 0;
    }
    ((GameObject*)obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    /* quest state machine: 0..3 the release, 4/6/7 the flight home,
       8..11 the talk spots, 12..15 the endgame cutscene parks */
    switch (sub->questState)
    {
    case 0: /* dormant; wake once the quest starts (0x94f) */
        if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
        }
        if (GameBit_Get(0x94f) != 0)
        {
            sub->questState = 1;
        }
        break;
    case 1: /* wait for its own cage to open (0x4E - one of the four
               clouddungeon cage bits 0x4C-0x4F); alert + take off */
        if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
        }
        if (GameBit_Get(0x4e) != 0)
        {
            sub->questState = 3;
            ObjAnim_SetCurrentMove(obj, 0x1a, lbl_803E4110, 0);
            ((GameObject*)obj)->unkF4 = 0;
            /* 0x48: broken out - the prison guard stands down on it */
            GameBit_Set(0x48, 1);
            sub->flagsA9B |= 1;
        }
        break;
    case 2: /* fly the escape curve; roost at the end */
        if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
        }
        sub->flagsA9B |= 2;
        if (fn_8019AF64((int*)obj, sub->pathBlock, lbl_803E4138, 0, &sub->moveSpeed) != 0)
        {
            sub->flagsA9B &= ~1;
            sub->questState = 4;
        }
        break;
    case 3: /* play the release sequence once */
        (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
        GameBit_Set(0x60, 1);
        sub->questState = 2;
        break;
    case 4: /* roost until the convergence cutscene parks him */
        if (GameBit_Get(0x57) != 0)
        {
            if (((CfGuardianMapData*)def)->variant != 1)
            {
                sub->questState = 0xf;
                sub->chatterAlt = 0;
            }
            else
            {
                sub->questState = 0xe;
                sub->chatterAlt = 0;
            }
        }
        else if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
            sub->chatterAlt = (s8)((sub->chatterAlt + 1) % 2);
        }
        break;
    case 6: /* free-fall to the ground, then settle at the curve home */
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
                hitDetectFn_800658a4((int*)obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                     ((GameObject*)obj)->anim.localPosZ, &ground, 0);
                *(s16*)obj = (s16)((0xc0 << (*(s16*)obj + 8)) >> 1);
                (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~0x400;
                if (ground <= lbl_803E4130)
                {
                    sub->landingPhase = 2;
                    ((GameObject*)obj)->anim.localPosY -= ground;
                    sub->chatterState = 1;
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
                            ObjGroup_AddObject(obj, 0x16);
                            sub->questState = 7;
                            ObjAnim_SetCurrentMove(obj, 0x1a, lbl_803E4110, 0);
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
                r = (f32)*(s16*)obj;
                r = r + w;
                *(s16*)obj = r;
                sub->moveSpeed = lbl_803E4148;
                if (GameBit_Get(0x8e9) != 0)
                {
                    ObjAnim_SetCurrentMove(obj, 0, lbl_803E4110, 0);
                    ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x32);
                    ((GameObject*)obj)->anim.velocityY = lbl_803E4110;
                    ObjGroup_RemoveObject(obj, 0x16);
                    {
                        f32 fz = lbl_803E4110;
                        ((GameObject*)obj)->anim.velocityX = fz;
                        ((GameObject*)obj)->anim.velocityY = lbl_803E414C;
                        ((GameObject*)obj)->anim.velocityZ = fz;
                    }
                    sub->landingPhase = 2;
                    sub->flagsA9B &= ~1;
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
                    f32 p2;
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
                    p2 = v2 * k;
                    stk.v[2] = p2;
                    ((GameObject*)obj)->anim.velocityX = v0 + ((GameObject*)obj)->anim.velocityX;
                    ((GameObject*)obj)->anim.velocityY = v1 + ((GameObject*)obj)->anim.velocityY;
                    ((GameObject*)obj)->anim.velocityZ = p2 + ((GameObject*)obj)->anim.velocityZ;
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
            if (sub->chatterState == 2)
            {
                sub->chatterState = 1;
            }
        }
        break;
    case 7: /* fly to the talk spot */
        if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
        }
        sub->flagsA9B |= 2;
        if (fn_8019AF64((int*)obj, sub->pathBlock, lbl_803E4138, 1, &sub->moveSpeed) != 0)
        {
            sub->questState = 8;
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x32);
        }
        break;
    case 8: /* talk spot: greet and head-track the player; 0x43 advances */
        {
            void* found = (void*)ObjGroup_FindNearestObject(3, obj, &nearDist);
            if (found != NULL && nearDist < lbl_803E4158)
            {
                dll_2E_func04(sub, found);
                ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
            }
        }
        if (nearDist > lbl_803E4158 && Vec_xzDistance(player + 0x18, (char*)obj + 0x18) < lbl_803E413C)
        {
            ((GameObject*)obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
            if ((sub->flagsA9B & 4) == 0 && lbl_80322954[sub->questState] != 0)
            {
                dll_2E_func0C(0xf, (u8*)&sub->homeYaw);
                sub->flagsA9B |= 5;
                lbl_80322954[sub->questState] = 0;
            }
            if (sub->chatterState == 2)
            {
                sub->chatterState = 1;
                sub->chatterAlt = (s8)((sub->chatterAlt + 1) % 2);
            }
        }
        else
        {
            if ((sub->flagsA9B & 4) == 0 && lbl_80322954[sub->questState] != 0xe)
            {
                sub->chatterState = 2;
                sub->flagsA9B |= 5;
                dll_2E_func0A(0xe, (int*)&sub->homeYaw);
                lbl_80322954[sub->questState] = 0xe;
            }
        }
        if ((sub->flagsA9B & 4) != 0
            && fn_8019B1D8((int*)obj, (int*)&sub->homeYaw, lbl_803E4128, (int)&sub->moveSpeed) != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x1a, lbl_803E4110, 0);
            sub->flagsA9B &= ~0x5;
        }
        if (GameBit_Get(0x43) != 0)
        {
            sub->questState = 9;
            sub->chatterAlt = 0;
        }
        break;
    case 9: /* second talk loop; 0x4be sends him onward */
        {
            void* found = (void*)ObjGroup_FindNearestObject(3, obj, &nearDist);
            if (found != NULL && nearDist < lbl_803E4158)
            {
                dll_2E_func04(sub, found);
            }
        }
        if (nearDist > lbl_803E4158 && Vec_xzDistance(player + 0x18, (char*)obj + 0x18) < lbl_803E413C)
        {
            if ((sub->flagsA9B & 4) == 0 && lbl_80322954[sub->questState] != 0)
            {
                dll_2E_func0C(0xf, (u8*)&sub->homeYaw);
                sub->flagsA9B |= 5;
                lbl_80322954[sub->questState] = 0;
            }
            if (sub->chatterState == 2)
            {
                sub->chatterState = 1;
                sub->chatterAlt = (s8)((sub->chatterAlt + 1) % 2);
            }
        }
        else
        {
            if ((sub->flagsA9B & 4) == 0 && lbl_80322954[sub->questState] != 0xe)
            {
                sub->chatterState = 2;
                sub->flagsA9B |= 5;
                dll_2E_func0A(0xe, (int*)&sub->homeYaw);
                lbl_80322954[sub->questState] = 0xe;
            }
        }
        if ((sub->flagsA9B & 4) != 0
            && fn_8019B1D8((int*)obj, (int*)&sub->homeYaw, lbl_803E4128, (int)&sub->moveSpeed) != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x1a, lbl_803E4110, 0);
            sub->flagsA9B &= ~0x5;
        }
        if (GameBit_Get(0x4be) != 0)
        {
            sub->questState = 0xa;
            ObjAnim_SetCurrentMove(obj, 0x1a, lbl_803E4110, 0);
            ((GameObject*)obj)->unkF4 = 0;
        }
        break;
    case 10: /* final flight out */
        if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
        }
        sub->flagsA9B |= 2;
        if (fn_8019AF64((int*)obj, sub->pathBlock, lbl_803E415C, 2, &sub->moveSpeed) != 0)
        {
            sub->questState = 0xb;
        }
        break;
    case 11: /* vanish: fade out and stop updating */
        if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
        }
        ((GameObject*)obj)->anim.alpha = 0;
        (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
        Obj_RemoveFromUpdateList((int*)obj);
        ((GameObject*)obj)->anim.flags |= 0x4000;
        sub->questState = 0xf;
        break;
    case 12: /* cutscene perch: sequence 0xB on demand (0x4b7) */
        if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
        }
        if (GameBit_Get(0x4b7) != 0)
        {
            (*gCameraInterface)->setTarget(obj);
            (*gObjectTriggerInterface)->runSequence(0xb, (void*)obj, -1);
            GameBit_Set(0x4b7, 0);
        }
        if (GameBit_Get(0x49a) != 0)
        {
            sub->questState = 0xd;
        }
        break;
    case 13: /* cutscene perch: sequence 0xA on demand (0x4b7) */
        if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
        }
        if (GameBit_Get(0x4b7) != 0)
        {
            (*gCameraInterface)->setTarget(obj);
            (*gObjectTriggerInterface)->runSequence(0xa, (void*)obj, -1);
            GameBit_Set(0x4b7, 0);
        }
        if (GameBit_Get(0x4aa) != 0)
        {
            sub->questState = 0xe;
        }
        break;
    case 14: /* parked, idle chatter only */
        if (sub->chatterState == 2)
        {
            sub->chatterState = 1;
        }
        break;
    case 15: /* parked and hidden */
        ((GameObject*)obj)->anim.flags |= 0x4000;
        Obj_RemoveFromUpdateList((int*)obj);
        (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
        break;
    }
    dll_2E_func03(obj, sub);
    if (ObjTrigger_IsSet(obj) != 0)
    {
        buttonDisable(0, 0x100);
        if ((*gGameUIInterface)->isEventReady(0x2e8) != 0)
        {
            GameBit_Set(0x4ab, 1);
        }
        else if (sub->chatterState == 1)
        {
            int* tbl = (int*)seqStreamLookupFn_8007fff8(lbl_8032284C, 0xf, sub->questState);
            int pick;
            if (fn_80296A14((int)player) > 3)
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
                sub->chatterState = 2;
                (*gObjectTriggerInterface)->runSequence(pick, (void*)obj, -1);
            }
        }
    }
    if (GameBit_Get(0x902) != 0)
    {
        int* tbl2 = (int*)seqStreamLookupFn_8007fff8(lbl_8032284C, 0xf, sub->questState);
        if (tbl2[0] != -1)
        {
            sub->chatterState = 2;
            (*gObjectTriggerInterface)->runSequence(tbl2[0], (void*)obj, -1);
            GameBit_Set(0x902, 0);
        }
    }
    {
        int mv = lbl_80322954[sub->questState];
        if (mv != -1 && (sub->flagsA9B & 1) == 0 && ((GameObject*)obj)->anim.currentMove != mv)
        {
            ObjAnim_SetCurrentMove(obj, mv, lbl_803E4110, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x50);
        }
    }
    if (((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, sub->moveSpeed, (f32)framesThisStep,
                                                                    stk.evbuf) != 0
        && (sub->flagsA9B & 1) != 0
        && ((GameObject*)obj)->anim.currentMove != 0x1a
        && ((GameObject*)obj)->anim.currentMove != 9)
    {
        sub->flagsA9B &= ~1;
    }
    fn_8019AE3C((int*)obj, (u8*)&stk + 12, &lbl_803DBE20);
    if (randFn_80080100(0x3c) != 0)
    {
        objAudioFn_800393f8(obj, (u8*)sub + 0x624, 0xdf, 0x1000, -1, 0);
    }
    objAnimFn_80038f38(obj, (u8*)sub + 0x624);
    characterDoEyeAnims((int*)obj, (u8*)sub + 0x654);
    if (sub->questState != GameBit_Get(0x4b))
    {
        GameBit_Set(0x4b, sub->questState);
    }
    return 0;
}

/* cfguardian_SeqFn: guardian message handler.
 * Persists position on a negative cue, otherwise picks the active/idle
 * heading pair and routes a move request; on the magic-grant message it
 * tops the player back up. Returns 1 if the move was consumed. */
int cfguardian_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int* sel;
    GuardianMsg stk;
    CfGuardianState* sub = ((GameObject*)obj)->extra;
    stk = lbl_802C22D8;
    if (((GameObject*)obj)->seqIndex < 0)
    {
        saveGame_saveObjectPos((int)obj);
        return 0;
    }
    if (sub->questState != 6)
    {
        sel = &stk.a;
    }
    else
    {
        sel = &stk.c;
    }
    if (animatedObjGetSeqId((int*)animUpdate) != 0x283)
    {
        if (dll_2E_func07(obj, animUpdate, (u8*)sub, (s16)sel[0], (s16)sel[1]) != 0)
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

void cfguardian_free(int* obj, int p2)
{
    char* extra = ((GameObject*)obj)->extra;
    if (p2 == 0)
    {
        char* state;
        int i;
        for (i = 0, state = extra; i < 6; i++)
        {
            int* sub = (int*)((CfGuardianState*)state)->linkedObjs[0];
            if (sub != NULL)
            {
                Obj_FreeObject(sub);
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
    stk1 = lbl_802C22C0;
    stk2 = lbl_802C22CC;
    if (sub == NULL) return;
    ObjMsg_AllocQueue(obj, 4);
    sub->questState = (u8)GameBit_Get(0x4b);
    ((GameObject*)obj)->unkF4 = 1;
    ((GameObject*)obj)->animEventCallback = (void*)cfguardian_SeqFn;
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    sub->landingPhase = 0;
    sub->moveSpeed = lbl_803E4110;
    sub->unkA90 = 6;
    sub->flagsA9B = 0;
    sub->flags611 = (u8)(sub->flags611 | 0x28);
    sub->chatterState = 1;
    sub->chatterAlt = 0;
    sub->chatterPick = 0;
    if (GameBit_Get(0x57) != 0)
    {
        sub->questState = 4;
        if ((s8)params[0x19] == 0)
        {
            ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | 0x4000);
            Obj_RemoveFromUpdateList(obj);
        }
    }
    else if (GameBit_Get(0x60) != 0 && (s8)params[0x19] == 0)
    {
        sub->questState = 4;
        dll_2E_func0A(8, obj);
    }
    ObjHits_EnableObject(obj);
    dll_2E_func05(obj, (u8*)sub, -0x2000, 0x2800, 4);
    dll_2E_func08((u8*)sub, 0x12c, 0x64);
    dll_2E_func09((u8*)sub, &stk2, &stk1, 4);
    objSeqInitFn_80080078(lbl_8032284C, 0xf);
    sub->flags611 = (u8)(sub->flags611 | 0x2);
}

void cfguardian_release(void)
{
}

void cfguardian_initialise(void)
{
}
