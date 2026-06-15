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

/* Trivial 4b 0-arg blr leaves. */

#define MEVT_TRIGGER(a, b, c) (*gMapEventInterface)->setObjGroupStatus((a), (b), (c))
#define MEVT_SET(a, b)        (*gMapEventInterface)->setMapAct((a), (b))
#define MEVT_QUERY(a)         (*gMapEventInterface)->getMapAct((a))

#undef MEVT_TRIGGER
#undef MEVT_SET
#undef MEVT_QUERY

extern u32 randomGetRange(int min, int max);

void imicepillar_free(void);

int imicepillar_getExtraSize(void);
int imicepillar_getObjectTypeId(void);

extern void objRenderFn_8003b8f4(f32);

extern void warpToMap(int mapId, int flags);

#define MEVT_TRIGGER(a, b, c) (*gMapEventInterface)->setObjGroupStatus((a), (b), (c))
#define MEVT_SET(a, b)        (*gMapEventInterface)->setMapAct((a), (b))

/* EN v1.0 0x801AC248  imicemountain_updateEventState: 8-state ice-mountain event machine dispatched
 * through jumptable_80323698 (states 1..7; state 0 idles). */
#undef MEVT_TRIGGER
#undef MEVT_SET

extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int kind, int id);

/* dll_16C_SeqFn: per-frame sequence callback - manage the spawned sub-object
 * from a small id table, then run the map-event sub-object state callbacks. */

/* dll_16C_syncSubObjectTransform: snapshot the map-event sub-object's transform into the boulder
 * extra block, optionally re-issuing a move on the sub-object first. */

extern void Music_Trigger(int track, int flag);

/* imicemountain_update: lazy-spawn the ambient effects, run the active state,
 * fade the warning timer, drive the music latch, then refresh the gamebit latches. */

extern u8 framesThisStep;

/* dll_16C_update: re-link the spawned sub-object, then while active/visible run
 * its move and fade opacity by distance to the player. */

/* crrockfall_init: derive the per-rock scale from the placement params, size the
 * capsule hitbox from the sub-object bounds, set up render flags, and pick the
 * state-table variant by object type. */

/* crrockfall_update: drive the falling-rock state machine - fade-in opacity by
 * height/distance, trigger the fall when the player is in range, integrate the
 * fall, then shatter (sfx + explosion) on impact. */

#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/DIM/DIMcannon.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"

STATIC_ASSERT(sizeof(ImAnimSpacecraftState) == 0x4);

STATIC_ASSERT(sizeof(ImSpaceThrusterState) == 0xC);

STATIC_ASSERT(sizeof(LinkLevControlState) == 0x10);

STATIC_ASSERT(sizeof(Lavaball1beState) == 0x14);

STATIC_ASSERT(sizeof(Lavaball1bfState) == 0x1C);

/* Obj_AllocObjectSetup(0x24,...) ring spawn buffer composed in
 * imspaceringgen_update. Head is the common ObjPlacement; tail
 * (0x18..0x1D) is file-local. */
typedef struct ImSpaceRingSetup
{
    ObjPlacement base; /* 0x00..0x17 */
    s8 unk18;          /* 0x18 */
    u8 pad19;          /* 0x19 */
    s16 unk1A;         /* 0x1A */
    s16 unk1C;         /* 0x1C */
    u8 pad1E[0x24 - 0x1E];
} ImSpaceRingSetup;

STATIC_ASSERT(offsetof(ImSpaceRingSetup, unk18) == 0x18);
STATIC_ASSERT(offsetof(ImSpaceRingSetup, unk1A) == 0x1A);
STATIC_ASSERT(offsetof(ImSpaceRingSetup, unk1C) == 0x1C);
STATIC_ASSERT(sizeof(ImSpaceRingSetup) == 0x24);

extern undefined4 ObjHits_EnableObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80057690();
extern undefined8 FUN_80286830();
extern undefined4 FUN_8028687c();
extern u32 lbl_803DDB48;
extern void Music_Trigger(int id, int p2);
extern f32 lbl_803E47C0;
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int* ObjList_GetObjects(int* startIndex, int* objectCount);
extern int Obj_AllocObjectSetup(int extraSize, int id);
extern f32 lbl_803E47C4;
extern void ModelLightStruct_free(void* light);

static inline int* DIMcannon_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

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

#pragma scheduling off
#pragma peephole off
void imspaceringgen_hitDetect(void)
{
}

void imspaceringgen_release(void)
{
}

void imspaceringgen_initialise(void)
{
}

void lavaball1be_hitDetect(void);

int imspaceringgen_getExtraSize(void) { return 0xc; }
int imspaceringgen_getObjectTypeId(void) { return 0x0; }
int linkb_levcontrol_getExtraSize(void);

void imspaceringgen_free(void) { lbl_803DDB48 = 0x0; }

void imspaceringgen_init(int* obj)
{
    ((GameObject*)obj)->unkF4 = 0;
    lbl_803DDB48 = (u32)obj;
}

void imanimspacecraft_update(int* obj);

void imicepillar_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

typedef struct
{
    int* ringA;
    int* ringB;
    u8 visible;
} RingGenState;

void imspaceringgen_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    u8* inner = ((GameObject*)obj)->extra;
    if (visible != 0 && (inner[8] != 0 || ((GameObject*)obj)->anim.alpha != 0))
    {
        ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E47C0);
    }
}

void imspaceringgen_update(s16* obj)
{
    extern void Obj_SetupObject(int obj, int a, int b, int c, int d); /* #57 */
    int i;
    int ring;
    u8* setup;
    RingGenState* state;
    int objIndex;
    int objCount;

    setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    if (state->ringA == NULL || state->ringB == NULL)
    {
        int* objs = ObjList_GetObjects(&objIndex, &objCount);
        for (objIndex = 0; objIndex < objCount; objIndex++)
        {
            int* o = (int*)objs[objIndex];
            if (((GameObject*)o)->anim.seqId == 0x164)
            {
                state->ringA = o;
            }
            if (((GameObject*)o)->anim.seqId == 0x168)
            {
                state->ringB = o;
            }
        }
    }
    else
    {
        int v;
        state->visible = ((int (*)(int*))((void**)*(void**)*(int*)((char*)state->ringB + 0x68))[9])(state->ringB);
        if (state->visible != 0)
        {
            v = ((GameObject*)obj)->anim.alpha + framesThisStep * 8;
            if (v > 0xff)
            {
                v = 0xff;
            }
        }
        else
        {
            v = ((GameObject*)obj)->anim.alpha - framesThisStep * 8;
            if (v < 0)
            {
                v = 0;
            }
        }
        ((GameObject*)obj)->anim.alpha = v;
        if (((GameObject*)obj)->unkF4 == 0 && Obj_IsLoadingLocked() != 0)
        {
            for (i = 0; i < 10; i++)
            {
                ring = Obj_AllocObjectSetup(0x24, 0x301);
                ((ImSpaceRingSetup*)ring)->base.posX = ((GameObject*)obj)->anim.localPosX;
                ((ImSpaceRingSetup*)ring)->base.posY = ((GameObject*)obj)->anim.localPosY;
                ((ImSpaceRingSetup*)ring)->base.posZ = ((GameObject*)obj)->anim.localPosZ;
                ((ImSpaceRingSetup*)ring)->unk18 = (s8)randomGetRange(0, 0xffff);
                ((ImSpaceRingSetup*)ring)->unk1A = (s16)randomGetRange(200, 400);
                if ((int)randomGetRange(0, 1) == 0)
                {
                    ((ImSpaceRingSetup*)ring)->unk1A = -((ImSpaceRingSetup*)ring)->unk1A;
                }
                ((ImSpaceRingSetup*)ring)->unk1C = (s16)randomGetRange(200, 400);
                if ((int)randomGetRange(0, 1) == 0)
                {
                    ((ImSpaceRingSetup*)ring)->unk1C = -((ImSpaceRingSetup*)ring)->unk1C;
                }
                ((ImSpaceRingSetup*)ring)->base.unk04[0] = setup[4];
                ((ImSpaceRingSetup*)ring)->base.unk04[2] = setup[6];
                ((ImSpaceRingSetup*)ring)->base.unk04[1] = 1;
                ((ImSpaceRingSetup*)ring)->base.unk04[3] = 0xff;
                Obj_SetupObject(ring, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                *(int*)&((GameObject*)obj)->anim.parent);
            }
            ((GameObject*)obj)->unkF4 = 1;
        }
        objMove((int)obj,
                ((GameObject*)state->ringA)->anim.localPosX - ((GameObject*)obj)->anim.localPosX,
                (lbl_803E47C4 + ((GameObject*)state->ringA)->anim.localPosY) - ((GameObject*)obj)->anim.localPosY,
                ((GameObject*)state->ringA)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ);
        ((GameObject*)obj)->anim.rotX = ((GameObject*)obj)->anim.rotX + framesThisStep * 0x100;
        ((GameObject*)obj)->anim.rotY = ((GameObject*)obj)->anim.rotY + framesThisStep * 0x20;
        ((GameObject*)obj)->anim.rotZ = ((GameObject*)obj)->anim.rotZ + framesThisStep * 0x40;
        *(int*)&((GameObject*)obj)->anim.parent = 0;
    }
}
