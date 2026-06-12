/* === moved from main/dll/DIM/DIMboulder.c [801AE0EC-801AE100) (TU re-split, docs/boundary_audit.md) === */
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

extern EffectInterface** gPartfxInterface;


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

void imanimspacecraft_modelMtxFn(void)
{
}

void imanimspacecraft_hitDetect(void)
{
}

void imanimspacecraft_release(void)
{
}

void imanimspacecraft_initialise(void)
{
}

void imspacethruster_hitDetect(void);
















/* 8b "li r3, N; blr" returners. */
int imanimspacecraft_getExtraSize(void) { return 0x4; }
int imanimspacecraft_getObjectTypeId(void) { return 0x0; }
int imspacethruster_getExtraSize(void);

/* Pattern wrappers. */

/* Init: clear obj->_F4 and record obj globally in lbl_803DDB48. */

/* If obj->_F4 == 0, set it to 1; else early-return. */
void imanimspacecraft_update(int* obj)
{
    if (((GameObject*)obj)->unkF4 != 0) return;
    ((GameObject*)obj)->unkF4 = 1;
}

/* Free: call vtable[6] on obj through global dll-services pointer. */
void imanimspacecraft_free(int* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

extern f32 lbl_803E4784;
extern char lbl_803AC948[];

void imanimspacecraft_init(int* obj)
{
    extern undefined4 GameBit_Set(int eventId, int value); /* #57 */
    f32 v;
    ((GameObject*)obj)->animEventCallback = (void*)imanimspacecraft_SeqFn;
    v = lbl_803E4784;
    *(f32*)(lbl_803AC948 + 0xc) = v;
    *(f32*)(lbl_803AC948 + 0x10) = v;
    *(f32*)(lbl_803AC948 + 0x14) = v;
    GameBit_Set(0xbeb, 1);
    GameBit_Set(0xbec, 1);
    GameBit_Set(0xbed, 1);
    GameBit_Set(0xbee, 1);
    GameBit_Set(0xbef, 1);
}

/* setScale (test): is bit (1 << idx) set in obj->_b8->_2? Returns 1/0. */
int imanimspacecraft_setScale(int* obj, int bitIdx)
{
    ImAnimSpacecraftState* p = (ImAnimSpacecraftState*)((GameObject*)obj)->extra;
    switch (p->maskBits & (1 << bitIdx))
    {
    default:
        return TRUE;
    case 0:
        return FALSE;
    }
}

/* lavaball1bf "consume" hook: only clear pending flag if both gates set. */
void lavaball1bf_func11(int* obj);

/* lavaball1bf "request" hook: set pending if gated, return success. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4780;
extern f32 lbl_803E4788;

void imicepillar_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void imanimspacecraft_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4780);
}

void imspacethruster_render(int p1, int p2, int p3, int p4, int p5, s8 visible);



/* if (o->_X == K) return A; else return B;  pattern. */


/* chained byte mask. */
u32 imanimspacecraft_func0B(int* obj) { return *((u8*)((int**)obj)[0xb8 / 4] + 0x3) & 0x4; }
u32 lavaball1be_func11(int* obj);


extern void Music_Trigger(int id, int p2);







extern f32 lbl_803E47A8, lbl_803E47AC, lbl_803E47B0, lbl_803E47B4, lbl_803E4798, lbl_803E4788;


























extern int ObjList_FindObjectById(int id);




extern int* objFindTexture(int* obj, int a, int b);
extern f32 lbl_803E4770, lbl_803E4774, lbl_803E4778, lbl_803E477C;

int imanimspacecraft_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    ImAnimSpacecraftState* state;
    int i;
    int* tex;

    state = ((GameObject*)obj)->extra;
    tex = objFindTexture(obj, 1, 0);
    *tex = ((state->flags >> 1 & 1) ^ 1) << 8;
    if (!(state->flags & 2))
    {
        if ((state->blinkTimer -= framesThisStep) < 0)
        {
            state->flags |= 2;
            state->blinkTimer = 0x78;
        }
    }
    else
    {
        state->flags &= ~2;
    }
    if (state->flags & 2)
    {
        *(f32*)(lbl_803AC948 + 0xc) = lbl_803E4770;
        *(f32*)(lbl_803AC948 + 0x10) = lbl_803E4774;
        *(f32*)(lbl_803AC948 + 0x14) = lbl_803E4778;
        (*gPartfxInterface)->spawnObject(obj, 0x133, lbl_803AC948, 4, -1, NULL);
        *(f32*)(lbl_803AC948 + 0xc) = lbl_803E477C;
        *(f32*)(lbl_803AC948 + 0x10) = lbl_803E4774;
        *(f32*)(lbl_803AC948 + 0x14) = lbl_803E4778;
        (*gPartfxInterface)->spawnObject(obj, 0x133, lbl_803AC948, 4, -1, NULL);
    }
    tex = objFindTexture(obj, 0, 0);
    *tex = 0x100;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u32 ev = animUpdate->eventIds[i];
        switch (ev)
        {
        case 1:
            state->maskBits = (u8)(state->maskBits ^ (1 << (ev - 1)));
            break;
        case 2:
            state->maskBits = (u8)(state->maskBits ^ (1 << (ev - 1)));
            break;
        case 3:
            state->maskBits = (u8)(state->maskBits ^ (1 << (ev - 1)));
            break;
        case 4:
            state->maskBits = (u8)(state->maskBits ^ (1 << (ev - 1)));
            break;
        case 5:
            state->maskBits = (u8)(state->maskBits ^ 0x70);
            break;
        case 6:
            state->flags = (u8)(state->flags ^ 8);
            break;
        case 7:
            state->flags = (u8)(state->flags ^ 4);
            break;
        }
    }
    return 0;
}

extern f32 lbl_803E478C, lbl_803E4790, lbl_803E4794, lbl_803E4798;




