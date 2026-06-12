#include "main/audio/sfx_ids.h"
#include "main/dll/blob10_struct.h"
#include "main/dll/crrockfallplacement_struct.h"
#include "main/dll/cr_types.h"
#include "main/dll/dll16cstate_struct.h"
#include "main/dll/magic_types.h"
#include "main/dll/imicemountainstate_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objseq.h"
#include "main/dll/DIM/DIMboulder.h"
#include "main/resource.h"




/*
 * Per-object extra state for the IM ice-mountain event controller
 * (imicemountain_getExtraSize == 0x14).
 */


STATIC_ASSERT(sizeof(IMIceMountainState) == 0x14);

/*
 * Per-object extra state for the magiclight proximity light
 * (magiclight_getExtraSize == 0x14 for non-0x172 types).
 */


STATIC_ASSERT(sizeof(MagicLightState) == 0x14);

/*
 * Per-object extra state for the dll_16C map-event boulder proxy
 * (dll_16C_getExtraSize == 0x24).
 */


STATIC_ASSERT(sizeof(Dll16CState) == 0x24);

/*
 * Per-object extra state for the crrockfall falling rock
 * (crrockfall_getExtraSize == 0x14).
 */




STATIC_ASSERT(sizeof(CrRockfallState) == 0x14);


extern undefined4 getLActions();
extern uint GameBit_Get(int eventId);
extern undefined8 GameBit_Set(int eventId, int value);
extern undefined4 FUN_8001771c();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined4 ObjHits_DisableObject();

extern undefined4 DAT_802c2a88;
extern undefined4 DAT_802c2a8c;
extern undefined4 DAT_802c2a90;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern f32 lbl_803E53D0;
extern f32 lbl_803E53E0;
extern f32 lbl_803E53F0;

/*
 * --INFO--
 *
 * Function: FUN_801ac248
 * EN v1.0 Address: 0x801AC248
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AC4FC
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ac248(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int param_9)
{
}


/*
 * --INFO--
 *
 * Function: FUN_801ad984
 * EN v1.0 Address: 0x801AD984
 * EN v1.0 Size: 420b
 * EN v1.1 Address: 0x801AD9F4
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801ad984(undefined8 param_1, undefined8 param_2, double param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9)
{
    int iVar1;
    undefined4 in_r9;
    undefined4 in_r10;
    float* pfVar2;
    double dVar3;
    double dVar4;

    if (((GameObject*)param_9)->anim.seqId != 0x172)
    {
        pfVar2 = ((GameObject*)param_9)->extra;
        iVar1 = FUN_80017a98();
        dVar3 = (double)FUN_8001771c((float*)(iVar1 + 0x18), (float*)&((GameObject*)param_9)->anim.worldPosX);
        dVar4 = (double)*pfVar2;
        if ((dVar4 <= dVar3) || (*(char*)((int)pfVar2 + 0xb) != '\0'))
        {
            if (((double)(float)((double)lbl_803E53D0 + dVar4) < dVar3) &&
                (*(char*)((int)pfVar2 + 0xb) != '\0'))
            {
                *(u8*)((int)pfVar2 + 0xb) = 0;
                getLActions(dVar3, dVar4, param_3, param_4, param_5, param_6, param_7, param_8, param_9, param_9,
                            (uint) * (ushort*)(pfVar2 + 2), 0, 0, 0, in_r9, in_r10);
            }
        }
        else
        {
            *(u8*)((int)pfVar2 + 0xb) = 1;
            getLActions(dVar3, dVar4, param_3, param_4, param_5, param_6, param_7, param_8, param_9, param_9,
                        (uint) * (ushort*)((int)pfVar2 + 6), 0, 0, 0, in_r9, in_r10);
        }
    }
    return 0;
}


/*
 * --INFO--
 *
 * Function: FUN_801adca0
 * EN v1.0 Address: 0x801ADCA0
 * EN v1.0 Size: 332b
 * EN v1.1 Address: 0x801ADD98
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801adca0(undefined2* param_1, undefined2* param_2, undefined4 param_3, undefined4 param_4,
                  undefined4 param_5, undefined4 param_6, char param_7, int param_8, int param_9)
{
    u8 uVar1;
    undefined4 local_28;
    undefined4 local_24;
    undefined4 local_20[5];

    if (((param_9 != 0) && (param_7 != '\0')) && (0 < param_8))
    {
        uVar1 = *(u8*)((int)param_2 + 0x37);
        *(char*)((int)param_2 + 0x37) = (char)param_8;
        (**(code**)(**(int**)(param_2 + 0x34) + 0x10))
            (param_2, param_3, param_4, param_5, param_6, 0xffffffff);
        *(u8*)((int)param_2 + 0x37) = uVar1;
    }
    *(undefined4*)(param_1 + 0x46) = *(undefined4*)(param_1 + 0xc);
    *(undefined4*)(param_1 + 0x48) = *(undefined4*)(param_1 + 0xe);
    *(undefined4*)(param_1 + 0x4a) = *(undefined4*)(param_1 + 0x10);
    *(undefined4*)(param_1 + 0x40) = *(undefined4*)(param_1 + 6);
    *(undefined4*)(param_1 + 0x42) = *(undefined4*)(param_1 + 8);
    *(undefined4*)(param_1 + 0x44) = *(undefined4*)(param_1 + 10);
    (**(code**)(**(int**)(param_2 + 0x34) + 0x28))(param_2, local_20, &local_24, &local_28);
    *(undefined4*)(param_1 + 6) = local_20[0];
    *(undefined4*)(param_1 + 8) = local_24;
    *(undefined4*)(param_1 + 10) = local_28;
    *param_1 = *param_2;
    param_1[1] = param_2[1];
    param_1[2] = param_2[2];
    *(undefined4*)(param_1 + 0xc) = *(undefined4*)(param_1 + 6);
    *(undefined4*)(param_1 + 0xe) = *(undefined4*)(param_1 + 8);
    *(undefined4*)(param_1 + 0x10) = *(undefined4*)(param_1 + 10);
    *(undefined4*)(param_1 + 0x12) = *(undefined4*)(param_2 + 0x12);
    *(undefined4*)(param_1 + 0x14) = *(undefined4*)(param_2 + 0x14);
    *(undefined4*)(param_1 + 0x16) = *(undefined4*)(param_2 + 0x16);
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_801addec
 * EN v1.0 Address: 0x801ADDEC
 * EN v1.0 Size: 896b
 * EN v1.1 Address: 0x801ADEE4
 * EN v1.1 Size: 576b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801addec(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10
             , int param_11, undefined4 param_12, uint* param_13, undefined4 param_14, undefined4 param_15
             , undefined4 param_16)
{
    uint uVar1;
    undefined2* puVar2;
    undefined4 uVar3;
    int iVar4;
    int* piVar5;
    int iVar6;
    undefined2 uStack_2a;
    undefined4 local_28;
    undefined4 local_24;
    undefined2 local_20;

    piVar5 = ((GameObject*)param_9)->extra;
    *(u8*)(piVar5 + 8) = 0xff;
    iVar6 = *piVar5;
    if (*(char*)(param_11 + 0x80) == '\x03')
    {
        *(u8*)((int)piVar5 + 0x21) = 0xff;
        *(u8*)(param_11 + 0x80) = 0;
    }
    local_28 = DAT_802c2a88;
    local_24 = DAT_802c2a8c;
    local_20 = DAT_802c2a90;
    if (*(char*)((int)piVar5 + 0x21) != *(char*)((int)piVar5 + 0x22))
    {
        if (*(int*)&((GameObject*)param_9)->childObjs[0] != 0)
        {
            param_1 = FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                   *(int*)&((GameObject*)param_9)->childObjs[0]);
            *(undefined4*)(param_9 + 200) = 0;
            *(u8*)(param_9 + 0xeb) = 0;
        }
        uVar1 = FUN_80017ae8();
        if ((uVar1 & 0xff) == 0)
        {
            *(u8*)((int)piVar5 + 0x22) = 0;
        }
        else
        {
            if (0 < *(char*)((int)piVar5 + 0x21))
            {
                puVar2 = FUN_80017aa4(0x18, (&uStack_2a)[*(char*)((int)piVar5 + 0x21)]);
                param_12 = 0xffffffff;
                param_13 = *(uint**)&((GameObject*)param_9)->anim.parent;
                uVar3 = FUN_80017ae4(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, puVar2,
                                     4, 0xff, 0xffffffff, param_13, param_14, param_15, param_16);
                *(undefined4*)(param_9 + 200) = uVar3;
                *(u8*)(param_9 + 0xeb) = 1;
            }
            *(u8*)((int)piVar5 + 0x22) = *(u8*)((int)piVar5 + 0x21);
        }
    }
    *(undefined2*)(param_11 + 0x6e) = *(undefined2*)(param_11 + 0x70);
    if ((iVar6 == 0) || (*(char*)(param_11 + 0x80) != '\x02'))
    {
        if ((iVar6 != 0) && (*(char*)(param_11 + 0x80) == '\x01'))
        {
            (**(code**)(**(int**)(iVar6 + 0x68) + 0x3c))(iVar6, 0);
            *(u8*)(param_11 + 0x80) = 0;
        }
    }
    else
    {
        piVar5[1] = (int)lbl_803E53F0;
        piVar5[2] = piVar5[5];
        piVar5[3] = piVar5[6];
        piVar5[4] = piVar5[7];
        (**(code**)(**(int**)(iVar6 + 0x68) + 0x3c))(iVar6, 2);
        FUN_800305f8((double)lbl_803E53E0, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0x100, 1, param_12, param_13, param_14, param_15, param_16);
        iVar4 = (int)((GameObject*)param_9)->anim.modelState;
        if (iVar4 != 0)
        {
            ((GameObject*)param_9)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
        *(ushort*)(param_11 + 0x6e) = *(ushort*)(param_11 + 0x6e) & ~0x4;
        *(u8*)(param_11 + 0x80) = 0;
    }
    if ((iVar6 != 0) && (iVar6 = (**(code**)(**(int**)(iVar6 + 0x68) + 0x38))(iVar6), iVar6 == 2))
    {
        *(ushort*)(param_11 + 0x6e) = *(ushort*)(param_11 + 0x6e) & 0xfffc;
    }
    return 0;
}


/* Trivial 4b 0-arg blr leaves. */
void imicemountain_free(void);

void imicemountain_hitDetect(void);

extern void gameBitFn_800ea2e0(int idx);
extern void unlockLevel(int a, int b, int c);
extern f32 lbl_803E46E0;

#define MEVT_TRIGGER(a, b, c) (*gMapEventInterface)->setAnimEvent((a), (b), (c))
#define MEVT_SET(a, b)        (*gMapEventInterface)->setMode((a), (b))
#define MEVT_QUERY(a)         (*gMapEventInterface)->getMode((a))

/* EN v1.0 0x801AC9C0  size: 828b  imicemountain_init: clear the ice-mountain
 * gamebit block, arm the map-event triggers, then branch on the queried level
 * state to set the boulder's start state and fire the appropriate triggers. */
#pragma scheduling off
void imicemountain_init(int* obj);
#pragma peephole reset
#pragma scheduling reset
#undef MEVT_TRIGGER
#undef MEVT_SET
#undef MEVT_QUERY
void crrockfall_free(void);

void crrockfall_hitDetect(void);

void magiclight_hitDetect(void)
{
}

void magiclight_release(void)
{
}

void magiclight_initialise(void)
{
}

extern u32 randomGetRange(int min, int max);
extern f32 lbl_803E4740;
extern f32 lbl_803E4744;

/* EN v1.0 0x801AD684  size: 344b  magiclight_init: seed header + update fn;
 * for the non-172 variants pick a random lifetime and, for type 0x16b, map
 * the spawn subtype to a light-pair / intensity preset. */
#pragma scheduling off
#pragma peephole off
void magiclight_init(int* obj, u8* params)
{
    MagicLightState* sub;
    ((GameObject*)obj)->unkF4 = 0;
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    ((GameObject*)obj)->animEventCallback = (void*)magiclight_SeqFn;
    if (((GameObject*)obj)->anim.seqId == 0x172)
    {
        return;
    }
    sub = ((GameObject*)obj)->extra;
    sub->lifetime = (s16)randomGetRange(0xc8, 0x258);
    sub->subtype = (s8) * (s16*)(params + 0x1a);
    sub->inRange = 0;
    if (((GameObject*)obj)->anim.seqId == 0x16b)
    {
        switch (sub->subtype)
        {
        case 0:
            sub->enterAction = 0x90;
            sub->leaveAction = 0x91;
            sub->triggerRadius = lbl_803E4740;
            break;
        case 1:
            sub->enterAction = 0x92;
            sub->leaveAction = 0x93;
            sub->triggerRadius = lbl_803E4740;
            break;
        default:
            sub->enterAction = 0x94;
            sub->leaveAction = 0x95;
            sub->triggerRadius = lbl_803E4744;
            break;
        case 3:
            sub->enterAction = 0x187;
            sub->leaveAction = 0x5;
            sub->triggerRadius = lbl_803E4740;
            break;
        }
        sub->unk10 = 0x12d;
    }
    else
    {
        sub->unk10 = 0x12d;
    }
}
#pragma peephole reset
#pragma scheduling reset
void dll_16C_release(void);

void dll_16C_initialise(void);


/* 8b "li r3, N; blr" returners. */
int imicemountain_getExtraSize(void);
int imicemountain_getObjectTypeId(void);
int crrockfall_getExtraSize(void);
int crrockfall_getObjectTypeId(void);
int magiclight_getObjectTypeId(void) { return 0x0; }
int dll_16C_getExtraSize(void);
int dll_16C_getObjectTypeId(void);

/* Pattern wrappers. */
extern void* lbl_803DDB40;
void crrockfall_initialise(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E46D8;
extern f32 lbl_803E4708;
extern f32 lbl_803E473C;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void imicemountain_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
#pragma peephole reset

#pragma peephole off
void crrockfall_render(int obj, int p1, int p2, int p3, int p4, s8 visible);

void magiclight_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    if (((GameObject*)obj)->anim.seqId == 0x172 && visible != 0)
    {
        objRenderFn_8003b8f4(lbl_803E473C);
    }
}
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
extern int hitDetectFn_80065e50(int obj, int** listOut, int p3, int p4, f32 x, f32 y, f32 z);
extern f32 lbl_803E4700;
extern f32 lbl_803E4704;
#pragma dont_inline on
f32 fn_801ACCFC(int obj);
#pragma dont_inline reset

void magiclight_free(int obj)
{
    MagicLightState* inner = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.seqId != 0x172)
    {
        if ((s8)inner->inRange != 0)
        {
            getLActions(obj, obj, (u16)inner->leaveAction, 0, 0, 0);
        }
        (*gExpgfxInterface)->freeSource2((u32)obj);
    }
}

void magiclight_update(int obj)
{
    if (((GameObject*)obj)->anim.seqId != 0x172 && ((GameObject*)obj)->unkF4 == 0)
    {
        *(s16*)obj = 0;
        ((GameObject*)obj)->anim.rotY = 0;
        ((GameObject*)obj)->anim.rotZ = 0;
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        ((GameObject*)obj)->unkF4 = 1;
    }
}
#pragma peephole reset
#pragma scheduling reset

/* if (o->_X == K) return A; else return B; */
#pragma peephole off
int magiclight_getExtraSize(int* obj)
{
    if (((GameObject*)obj)->anim.seqId == 0x172) return 0x0;
    return 0x14;
}
#pragma peephole reset

extern void Obj_FreeObject(int*);

void dll_16C_free(int* obj);

/* conditional init/free pair. */
void crrockfall_release(void);

/* dll_16C_hitDetect: if extra->p && vtable(p,0x38)()==2, sync its transform into obj. */
extern void dll_16C_syncSubObjectTransform(void* a, void* b, int c, int d, int e, int f, int g, int h, int i);
#pragma scheduling off
#pragma peephole off
void dll_16C_hitDetect(void* obj);
#pragma peephole reset
#pragma scheduling reset

extern int objUpdateOpacity(int* obj);
extern void ObjPath_GetPointWorldPosition(int* obj, int idx, f32* x, f32* y, f32* z, int e);
extern f32 lbl_803E4758;
#pragma scheduling off
#pragma peephole off
void dll_16C_render(int* obj, int p1, int p2, int p3, int p4, s8 visible);
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
int IMIceMountain_SeqFn(void* obj, int unused, ObjAnimUpdateState* animUpdate);
#pragma scheduling reset

/* dll_16C_init: install callback, configure sub-obj, init extra fields from arg. */
#pragma scheduling off
void dll_16C_init(void* obj, void* arg2);
#pragma scheduling reset

extern float Vec_distance(float* a, float* b);
extern f32 lbl_803E4738;
#pragma scheduling off
#pragma peephole off
int magiclight_SeqFn(int* obj)
{
    MagicLightState* state;
    int* player;
    f32 dist;

    if (((GameObject*)obj)->anim.seqId == 370) return 0;

    state = ((GameObject*)obj)->extra;
    player = (int*)Obj_GetPlayerObject();
    dist = Vec_distance(&((GameObject*)player)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX);

    if (dist < state->triggerRadius && state->inRange == 0)
    {
        state->inRange = 1;
        getLActions(obj, obj, (u16)state->enterAction, 0, 0, 0);
    }
    else if (dist > lbl_803E4738 + state->triggerRadius && state->inRange != 0)
    {
        state->inRange = 0;
        getLActions(obj, obj, (u16)state->leaveAction, 0, 0, 0);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern void getEnvfxAct(int* obj, int* target, int id, int p);
extern void fn_801AC108(int* obj, int* extra);
extern CloudActionInterface** gCloudActionInterface;
extern void warpToMap(int mapId, int flags);

#define MEVT_TRIGGER(a, b, c) (*gMapEventInterface)->setAnimEvent((a), (b), (c))
#define MEVT_SET(a, b)        (*gMapEventInterface)->setMode((a), (b))

/* EN v1.0 0x801AC248  imicemountain_updateEventState: 8-state ice-mountain event machine dispatched
 * through jumptable_80323698 (states 1..7; state 0 idles). */
#pragma scheduling off
#pragma peephole off
void imicemountain_updateEventState(int* obj);
#pragma peephole reset
#pragma scheduling reset
#undef MEVT_TRIGGER
#undef MEVT_SET

extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int kind, int id);
extern int Obj_SetupObject(int handle, int a, int b, int c, int d);
extern f32 lbl_803E4748;
extern u8 lbl_802C2308[];



/* dll_16C_SeqFn: per-frame sequence callback - manage the spawned sub-object
 * from a small id table, then run the map-event sub-object state callbacks. */
#pragma scheduling off
#pragma peephole off
int dll_16C_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);
#pragma peephole reset
#pragma scheduling reset

/* dll_16C_syncSubObjectTransform: snapshot the map-event sub-object's transform into the boulder
 * extra block, optionally re-issuing a move on the sub-object first. */
#pragma scheduling off
#pragma peephole off
void dll_16C_syncSubObjectTransform(void* a, void* b, int c, int d, int e, int f, int g, int h, int i);
#pragma peephole reset
#pragma scheduling reset

extern void fn_801AC01C(int* obj);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShow(int id);
extern void Music_Trigger(int track, int flag);
extern void SCGameBitLatch_Update(void* state, int mask, int a, int b, int c, int d);
extern int* gSHthorntailAnimationInterface;
extern f32 timeDelta;
extern f32 lbl_803E46DC;

/* imicemountain_update: lazy-spawn the ambient effects, run the active state,
 * fade the warning timer, drive the music latch, then refresh the gamebit latches. */
#pragma scheduling off
void imicemountain_update(int* obj);
#pragma peephole reset
#pragma scheduling reset

extern int* ObjGroup_GetObjects(int group, int* countOut);
extern u8 framesThisStep;
extern f32 lbl_803E474C;
extern f32 lbl_803E475C;
extern f32 lbl_803E4760;
extern f32 lbl_803E4764;

/* dll_16C_update: re-link the spawned sub-object, then while active/visible run
 * its move and fade opacity by distance to the player. */
#pragma scheduling off
#pragma peephole off
void dll_16C_update(int* obj);
#pragma peephole reset
#pragma scheduling reset

extern u8 lbl_803236B8[];
extern f32 lbl_803E4730;

/* crrockfall_init: derive the per-rock scale from the placement params, size the
 * capsule hitbox from the sub-object bounds, set up render flags, and pick the
 * state-table variant by object type. */
#pragma scheduling off
#pragma peephole off
void crrockfall_init(int* obj, u8* params);
#pragma peephole reset
#pragma scheduling reset

extern void fn_800628CC(int* obj);
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern void Sfx_PlayFromObject(int* obj, int sfx);
extern void Sfx_StopObjectChannel(int* obj, int channel);
extern void spawnExplosion(int* obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);
extern f32 lbl_803E46E8;
extern f32 lbl_803E46EC;
extern f32 lbl_803E46F0;
extern f32 lbl_803E470C;
extern f32 lbl_803E4710;
extern f32 lbl_803E4714;
extern f32 lbl_803E4718;
extern f32 lbl_803E471C;
extern f32 lbl_803E4720;

/* crrockfall_update: drive the falling-rock state machine - fade-in opacity by
 * height/distance, trigger the fall when the player is in range, integrate the
 * fall, then shatter (sfx + explosion) on impact. */
#pragma scheduling off
#pragma peephole off
void crrockfall_update(int* obj);
#pragma peephole reset
#pragma scheduling reset
