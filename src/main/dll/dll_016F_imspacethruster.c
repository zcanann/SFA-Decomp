#pragma scheduling on
#pragma peephole on
#include "main/effect_interfaces.h"
#include "main/dll/linklevcontrolstate_struct.h"
#include "main/dll/lavaball1bfstate_struct.h"
#include "main/dll/imspacethrusterstate_struct.h"
#include "main/dll/lavaball1bestate_struct.h"
#include "main/dll/imanimspacecraftstate_struct.h"
#include "main/dll/dll16cstate_struct.h"
#include "main/dll/magiclightstate_struct.h"
#include "main/dll/crrockfall_types.h"
#include "main/objseq.h"



/*
 * Per-object extra state for the IM ice-mountain event controller
 * (imicemountain_getExtraSize == 0x14).
 */
typedef struct IMIceMountainState
{
    u8 eventState; /* 0..7 event machine (imicemountain_updateEventState) */
    u8 pad01[3];
    s32 latchFlags; /* SCGameBitLatch record; bit 1 = latch fired this frame */
    s8 warpCountdown; /* state 6: frames until warpToMap(0x1A) */
    u8 pad09;
    s16 musicTrack; /* -1 or 26; Music_Trigger edge latch */
    u8 mapEventState; /* MEVT_QUERY result at init (1/2/5) */
    u8 pad0D[3];
    f32 warningTextTimer; /* shows text 0x351 while above the floor value */
} IMIceMountainState;

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


extern uint GameBit_Get(int eventId);
extern undefined4 FUN_80017ac8();


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


/* Trivial 4b 0-arg blr leaves. */



#define MEVT_TRIGGER(a, b, c) (*gMapEventInterface)->setAnimEvent((a), (b), (c))
#define MEVT_SET(a, b)        (*gMapEventInterface)->setMode((a), (b))
#define MEVT_QUERY(a)         (*gMapEventInterface)->getMode((a))

/* EN v1.0 0x801AC9C0  size: 828b  imicemountain_init: clear the ice-mountain
 * gamebit block, arm the map-event triggers, then branch on the queried level
 * state to set the boulder's start state and fire the appropriate triggers. */
#pragma scheduling off
#pragma peephole reset
#pragma scheduling reset
#undef MEVT_TRIGGER
#undef MEVT_SET
#undef MEVT_QUERY






/* EN v1.0 0x801AD684  size: 344b  magiclight_init: seed header + update fn;
 * for the non-172 variants pick a random lifetime and, for type 0x16b, map
 * the spawn subtype to a light-pair / intensity preset. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


void imicepillar_free(void);

/* 8b "li r3, N; blr" returners. */
int imicepillar_getExtraSize(void);
int imicepillar_getObjectTypeId(void);

/* Pattern wrappers. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
#pragma peephole reset

#pragma peephole off

#pragma peephole reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset


#pragma peephole reset
#pragma scheduling reset

/* if (o->_X == K) return A; else return B; */
#pragma peephole off
#pragma peephole reset



/* conditional init/free pair. */

/* dll_16C_hitDetect: if extra->p && vtable(p,0x38)()==2, sync its transform into obj. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset

/* dll_16C_init: install callback, configure sub-obj, init extra fields from arg. */
#pragma scheduling off
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

extern void warpToMap(int mapId, int flags);

#define MEVT_TRIGGER(a, b, c) (*gMapEventInterface)->setAnimEvent((a), (b), (c))
#define MEVT_SET(a, b)        (*gMapEventInterface)->setMode((a), (b))

/* EN v1.0 0x801AC248  imicemountain_updateEventState: 8-state ice-mountain event machine dispatched
 * through jumptable_80323698 (states 1..7; state 0 idles). */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset
#undef MEVT_TRIGGER
#undef MEVT_SET

extern u8 lbl_802C2308[];


/* dll_16C_SeqFn: per-frame sequence callback - manage the spawned sub-object
 * from a small id table, then run the map-event sub-object state callbacks. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

/* dll_16C_syncSubObjectTransform: snapshot the map-event sub-object's transform into the boulder
 * extra block, optionally re-issuing a move on the sub-object first. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

extern void Music_Trigger(int track, int flag);

/* imicemountain_update: lazy-spawn the ambient effects, run the active state,
 * fade the warning timer, drive the music latch, then refresh the gamebit latches. */
#pragma scheduling off
#pragma scheduling reset

extern u8 framesThisStep;

/* dll_16C_update: re-link the spawned sub-object, then while active/visible run
 * its move and fade opacity by distance to the player. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

extern u8 lbl_803236B8[];

/* crrockfall_init: derive the per-rock scale from the placement params, size the
 * capsule hitbox from the sub-object bounds, set up render flags, and pick the
 * state-table variant by object type. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


/* crrockfall_update: drive the falling-rock state machine - fade-in opacity by
 * height/distance, trigger the fall when the player is in range, integrate the
 * fall, then shatter (sfx + explosion) on impact. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling reset

#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/DIM/DIMcannon.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"





/* imanimspacecraft_getExtraSize == 0x4. */


STATIC_ASSERT(sizeof(ImAnimSpacecraftState) == 0x4);

/* imspacethruster_getExtraSize == 0xc. */


STATIC_ASSERT(sizeof(ImSpaceThrusterState) == 0xC);

/* link_levcontrol_getExtraSize == 0x10. */


STATIC_ASSERT(sizeof(LinkLevControlState) == 0x10);

/* lavaball1be extra (getExtraSize 0x14 for the non-0x1fa variant). */


STATIC_ASSERT(sizeof(Lavaball1beState) == 0x14);

/* lavaball1bf_getExtraSize == 0x1c (launcher). */


STATIC_ASSERT(sizeof(Lavaball1bfState) == 0x1C);

static inline int* DIMcannon_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

extern undefined4 ObjHits_EnableObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80057690();
extern undefined8 FUN_80286830();
extern undefined4 FUN_8028687c();



/*
 * --INFO--
 *
 * Function: imicepillar_render
 * EN v1.0 Address: 0x801AE100
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801AE134
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_801ae0_dropped_old_imicepillar_render(undefined8 param_1, undefined8 param_2, undefined8 param_3,
                                               undefined8 param_4,
                                               undefined8 param_5, undefined8 param_6, undefined8 param_7,
                                               undefined8 param_8,
                                               int param_9)
{
    if (*(int*)&((GameObject*)param_9)->childObjs[0] != 0)
    {
        FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     *(int*)&((GameObject*)param_9)->childObjs[0]);
    }
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ae184
 * EN v1.0 Address: 0x801AE184
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x801AE160
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ae184(undefined4 param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4,
                  undefined4 param_5, char param_6)
{
    extern undefined4 FUN_801adca0(); /* #57 */
    extern undefined4 ObjPath_GetPointWorldPosition(); /* #57 */
    u8 uVar1;
    bool bVar2;
    undefined2* puVar3;
    uint uVar4;
    int iVar5;
    undefined4 uVar6;
    undefined2* puVar7;
    undefined4* puVar8;
    undefined8 uVar9;

    uVar9 = FUN_80286830();
    puVar3 = (undefined2*)((ulonglong)uVar9 >> 0x20);
    if (puVar3[0x23] == 0x373)
    {
        FUN_8003b818((int)puVar3);
    }
    else
    {
        uVar4 = GameBit_Get(0x6e);
        if ((uVar4 == 0) || (uVar4 = GameBit_Get(0x382), uVar4 != 0))
        {
            puVar8 = *(undefined4**)(puVar3 + 0x5c);
            puVar7 = (undefined2*)*puVar8;
            bVar2 = false;
            if ((puVar7 != (undefined2*)0x0) &&
                (iVar5 = (**(code**)(**(int**)(puVar7 + 0x34) + 0x38))(puVar7), iVar5 == 2))
            {
                bVar2 = true;
            }
            if (bVar2)
            {
                puVar3[3] = puVar3[3] | 8;
                uVar6 = FUN_80057690((int)puVar7);
                param_6 = (char)uVar6;
                FUN_801adca0(puVar3, puVar7, (int)uVar9, param_3, param_4, param_5, param_6,
                             (uint) * (byte*)(puVar8 + 8), 1);
            }
            else
            {
                puVar3[3] = puVar3[3] & ~0x8;
            }
            if ((param_6 != '\0') && (*(char*)(puVar8 + 8) != '\0'))
            {
                uVar1 = *(u8*)((int)puVar3 + 0x37);
                if (bVar2)
                {
                    *(char*)((int)puVar3 + 0x37) = *(char*)(puVar8 + 8);
                }
                FUN_8003b818((int)puVar3);
                ObjPath_GetPointWorldPosition(puVar3, 1, (float*)(puVar8 + 5), puVar8 + 6, (float*)(puVar8 + 7), 0);
                *(u8*)((int)puVar3 + 0x37) = uVar1;
            }
        }
    }
    FUN_8028687c();
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_801ae9e4
 * EN v1.0 Address: 0x801AE9E4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801AE9BC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801aea18
 * EN v1.0 Address: 0x801AEA18
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801AE9EC
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801aea40
 * EN v1.0 Address: 0x801AEA40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801AEA38
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801aea44
 * EN v1.0 Address: 0x801AEA44
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x801AEACC
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801b0190
 * EN v1.0 Address: 0x801B0190
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801AFE04
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801b01e8
 * EN v1.0 Address: 0x801B01E8
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x801AFE64
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void imicepillar_hitDetect(void);

void imicepillar_update(void);

void imicepillar_init(void);

void imicepillar_release(void);

void imicepillar_initialise(void);

ObjectDescriptor gIMIcePillarObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)imicepillar_initialise,
    (ObjectDescriptorCallback)imicepillar_release,
    0,
    (ObjectDescriptorCallback)imicepillar_init,
    (ObjectDescriptorCallback)imicepillar_update,
    (ObjectDescriptorCallback)imicepillar_hitDetect,
    (ObjectDescriptorCallback)imicepillar_render,
    (ObjectDescriptorCallback)imicepillar_free,
    (ObjectDescriptorCallback)imicepillar_getObjectTypeId,
    imicepillar_getExtraSize,
};





void imspacethruster_hitDetect(void)
{
}

void imspacethruster_release(void)
{
}

void imspacethruster_initialise(void)
{
}

void imspacering_free(void);













/* 8b "li r3, N; blr" returners. */
int imspacethruster_getExtraSize(void) { return 0xc; }
int imspacethruster_getObjectTypeId(void) { return 0x0; }
int imspacering_getExtraSize(void);

/* Pattern wrappers. */

/* Init: clear obj->_F4 and record obj globally in lbl_803DDB48. */

/* If obj->_F4 == 0, set it to 1; else early-return. */

/* Free: call vtable[6] on obj through global dll-services pointer. */



/* setScale (test): is bit (1 << idx) set in obj->_b8->_2? Returns 1/0. */

/* lavaball1bf "consume" hook: only clear pending flag if both gates set. */

/* lavaball1bf "request" hook: set pending if gated, return success. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4788;

void imicepillar_render(int p1, int p2, int p3, int p4, int p5, s8 visible);


void imspacethruster_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4788);
}

void imspacering_render(int p1, int p2, int p3, int p4, int p5, s8 visible);


/* if (o->_X == K) return A; else return B;  pattern. */


/* chained byte mask. */


extern void Music_Trigger(int id, int p2);







extern void ObjModel_SetBlendChannelTargets(int* model, int channel, int p3, int p4, f32 weight, int p6);
extern void ObjModel_SetBlendChannelWeight(int* model, int channel, f32 weight);
extern f32 lbl_803E47A8, lbl_803E47AC, lbl_803E47B0, lbl_803E47B4, lbl_803E4798, lbl_803E4788;
extern s16 lbl_80323818[], lbl_80323824[];

void imspacethruster_init(int* obj, u8* param2)
{
    ObjAnimComponent* objAnim;
    ImSpaceThrusterState* sub = ((GameObject*)obj)->extra;
    int* model;
    objAnim = (ObjAnimComponent*)obj;
    *(s16*)obj = (s16)((s8)param2[0x18] << 8);
    ((GameObject*)obj)->anim.rotY = *(s16*)((char*)param2 + 0x1a);
    objAnim->bankIndex = (s8) * (s16*)((char*)param2 + 0x1c);
    sub->kind = param2[0x19];
    switch (sub->kind)
    {
    case 0:
    case 1:
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E47A8;
        break;
    case 2:
    case 3:
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E47AC;
        break;
    case 5:
    case 6:
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E47B0;
        break;
    case 4:
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E47B4;
        break;
    }
    model = DIMcannon_GetActiveModel(obj);
    ObjModel_SetBlendChannelTargets(model, 0, -1, 0, lbl_803E4798, 0);
    ObjModel_SetBlendChannelWeight(model, 0, lbl_803E4788);
    {
        u32 v = sub->kind;
        if (v < 5)
        {
            *(int*)&sub->bufA = (int)mmAlloc(0x28, 0x12, 0);
            getTabEntry(sub->bufA, 0xc, lbl_80323818[v] * 0x28, 0x28);
            *(int*)&sub->bufB = (int)mmAlloc(0x28, 0x12, 0);
            getTabEntry(sub->bufB, 0xc, lbl_80323824[v] * 0x28, 0x28);
        }
    }
    ((GameObject*)obj)->anim.alpha = 0;
}

void link_levcontrol_init(int* obj);











extern void mm_free(void* p);





void imspacethruster_free(int obj)
{
    ImSpaceThrusterState* inner = ((GameObject*)obj)->extra;
    if (inner->bufA != 0) mm_free(inner->bufA);
    if (inner->bufB != 0) mm_free(inner->bufB);
}

void dimlogfire_free(int* obj, int mode);







extern int ObjList_FindObjectById(int id);




extern int* objFindTexture(int* obj, int a, int b);


extern f32 lbl_803E478C, lbl_803E4790, lbl_803E4794, lbl_803E4798;

void imspacethruster_update(int* obj)
{
    ImSpaceThrusterState* state;
    int mode;
    s16 v;
    int* tex;

    state = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.parent != NULL)
    {
        mode = ((s16 (*)(int, int))((void**)*(void**)*(int*)(*(int*)&((GameObject*)obj)->anim.parent + 0x68))[8])(
            *(int*)&((GameObject*)obj)->anim.parent, state->kind);
        switch (state->phase)
        {
        case 0:
            if (mode == 1)
            {
                ObjModel_SetBlendChannelTargets(DIMcannon_GetActiveModel(obj), 0, -1, 0, lbl_803E478C, 0x10);
                ((GameObject*)obj)->anim.alpha = 0xff;
                state->phase = 1;
            }
            else
            {
                int d = ((GameObject*)obj)->anim.alpha - framesThisStep * 8;
                if (d < 0)
                {
                    d = 0;
                }
                ((GameObject*)obj)->anim.alpha = d;
            }
            break;
        case 1:
            if (mode == 0)
            {
                ObjModel_SetBlendChannelTargets(DIMcannon_GetActiveModel(obj), 0, -1, 0, lbl_803E4790, 0x10);
                state->blendTimer = 0xb4;
                ((GameObject*)obj)->anim.alpha = 0xa4;
                state->phase = 2;
            }
            break;
        case 2:
            if (mode == 1)
            {
                state->phase = 1;
            }
            else
            {
                if ((state->blendTimer -= framesThisStep) < 0)
                {
                    state->phase = 0;
                }
            }
            break;
        }
        if (state->kind < 5)
        {
            f32 a = (f32)((GameObject*)obj)->anim.alpha / lbl_803E4794;
            if (a > lbl_803E4788)
            {
                a = lbl_803E4788;
            }
            else if (a < lbl_803E4798)
            {
                a = lbl_803E4798;
            }
            ((void (*)(int, f32, int))((void**)*(void**)*(int*)(*(int*)&((GameObject*)obj)->anim.parent + 0x68))[10])(
                *(int*)&((GameObject*)obj)->anim.parent, a, state->kind);
        }
        tex = objFindTexture(obj, 0, 0);
        v = -*(s16*)((char*)tex + 0xa);
        v += 0x100;
        if (v > 0x800)
        {
            v -= 0x800;
        }
        *(s16*)((char*)tex + 0xa) = -v;
        tex = objFindTexture(obj, 1, 0);
        v = -*(s16*)((char*)tex + 0xa);
        v += 0xa0;
        if (v > 0x800)
        {
            v -= 0x800;
        }
        *(s16*)((char*)tex + 0xa) = -v;
    }
}


void lavaball1bf_update(int* obj);

