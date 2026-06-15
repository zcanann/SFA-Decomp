/* DLL 0x1BF - DIMLavaball [801AE0EC-801AE100) */
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
extern f32 timeDelta;

/* imicemountain_update: lazy-spawn the ambient effects, run the active state,
 * fade the warning timer, drive the music latch, then refresh the gamebit latches. */

/* dll_16C_update: re-link the spawned sub-object, then while active/visible run
 * its move and fade opacity by distance to the player. */

/* crrockfall_init: derive the per-rock scale from the placement params, size the
 * capsule hitbox from the sub-object bounds, set up render flags, and pick the
 * state-table variant by object type. */

/* crrockfall_update: drive the falling-rock state machine - fade-in opacity by
 * height/distance, trigger the fall when the player is in range, integrate the
 * fall, then shatter (sfx + explosion) on impact. */

#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIMcannon.h"

typedef struct Lavaball1bfPlacement
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x1E - 0x19];
    s16 unk1E;
    u8 pad20[0x24 - 0x20];
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} Lavaball1bfPlacement;

STATIC_ASSERT(sizeof(ImAnimSpacecraftState) == 0x4);

STATIC_ASSERT(sizeof(ImSpaceThrusterState) == 0xC);

STATIC_ASSERT(sizeof(LinkLevControlState) == 0x10);

STATIC_ASSERT(sizeof(Lavaball1beState) == 0x14);

STATIC_ASSERT(sizeof(Lavaball1bfState) == 0x1C);

extern undefined4 FUN_8003b818();
extern undefined4 FUN_80057690();
extern undefined8 FUN_80286830();
extern undefined4 FUN_8028687c();
extern f32 lbl_803E4810;
extern void Music_Trigger(int id, int p2);
extern int Obj_AllocObjectSetup(int extraSize, int id);
extern f32 lbl_803E4814;

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
void lavaball1bf_hitDetect(void)
{
}

void lavaball1bf_release(void)
{
}

void lavaball1bf_initialise(void)
{
}

int lavaball1bf_getExtraSize(void) { return 0x1c; }
int lavaball1bf_getObjectTypeId(void) { return 0x0; }
int dimlogfire_getExtraSize(void);

void lavaball1bf_func11(int* obj)
{
    Lavaball1bfState* p = (Lavaball1bfState*)((int**)obj)[0xb8 / 4];
    if (p->gateA == 0) return;
    if (p->pending == 0) return;
    p->pending = 0;
}

int lavaball1bf_setScale(int* obj)
{
    Lavaball1bfState* p;
    obj = (int*)((int**)obj)[0xb8 / 4];
    p = (Lavaball1bfState*)obj;
    if (p->gateA == 0) return 0;
    if (p->pending == 0)
    {
        p->pending = 1;
        return 1;
    }
    return 0;
}


void lavaball1bf_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4810);
}


void lavaball1bf_init(s16* obj, u8* p)
{
    Lavaball1bfState* inner;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)p[0x1c] << 8);
    inner = ((GameObject*)obj)->extra;
    inner->firePeriod = (f32) * (s16*)(p + 0x18);
    inner->fireTimer = lbl_803E4814;
    inner->gateA = p[0x1d];
    inner->gateB = (u8)GameBit_Get((int)*(s16*)(p + 0x22));
    if (*(s16*)(p + 0x24) == -1 && inner->gateB == 0)
    {
        inner->soloLatch = 1;
    }
    ((GameObject*)obj)->objectFlags |= 0x6000;
}

void lavaball1bf_free(int obj, int mode)
{
    extern void Obj_FreeObject(void* o); /* #57 */
    Lavaball1bfState* inner = ((GameObject*)obj)->extra;
    if (mode == 0 && inner->spawnedObj != 0)
    {
        Obj_FreeObject(inner->spawnedObj);
    }
}


void lavaball1bf_update(int* obj)
{
    extern void Obj_SetupObject(int obj, int a, int b, int c, int d); /* #57 */
    u8* setup;
    Lavaball1bfState* state;
    int* spawned;
    f32 t;

    state = ((GameObject*)obj)->extra;
    setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    state->gbState = GameBit_Get(((Lavaball1bfPlacement*)setup)->unk24);
    if (state->soloLatch != 0)
    {
        if (GameBit_Get(((Lavaball1bfPlacement*)setup)->unk1E) != 0)
        {
            state->gbState = 1;
            state->soloLatch = 0;
            state->fireTimer = lbl_803E4814;
        }
        else
        {
            state->gbState = 0;
        }
    }
    if (*(void**)&state->spawnedObj == NULL && Obj_IsLoadingLocked() != 0)
    {
        int s = Obj_AllocObjectSetup(0x24, 0x18d);
        *(u8*)(s + 2) = 9;
        *(u8*)(s + 4) = 2;
        *(u8*)(s + 6) = 0xff;
        *(u8*)(s + 5) = 4;
        *(u8*)(s + 7) = 0x50;
        *(f32*)(s + 8) = ((GameObject*)obj)->anim.localPosX;
        *(f32*)(s + 0xc) = ((GameObject*)obj)->anim.localPosY;
        *(f32*)(s + 0x10) = ((GameObject*)obj)->anim.localPosZ;
        *(s8*)(s + 0x18) = (s8)setup[0x1c];
        *(s16*)(s + 0x1a) = setup[0x1a];
        *(s16*)(s + 0x1c) = setup[0x1b];
        *(int*)(s + 0x14) = ((ObjPlacement*)setup)->mapId;
        *(int*)&state->spawnedObj = ((int (*)(int, int, int, int, int))Obj_SetupObject)(
            s, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
    }
    spawned = state->spawnedObj;
    t = state->fireTimer - timeDelta;
    state->fireTimer = t;
    if (t <= lbl_803E4814 && ((int (*)(int*))((void**)*(void**)*(int*)((char*)spawned + 0x68))[9])(spawned) != 0)
    {
        if (state->gbState != 0)
        {
            int a;
            if (GameBit_Get(((Lavaball1bfPlacement*)setup)->unk1E) != 0 && state->gateB == 0)
            {
                a = setup[0x20];
                state->gateB = 1;
            }
            else
            {
                a = setup[0x1a];
            }
            ((void (*)(int*, int, int))((void**)*(void**)*(int*)((char*)spawned + 0x68))[8])(spawned, a, setup[0x1b]);
        }
        state->fireTimer = state->firePeriod + (f32)(int)
        randomGetRange(0, 0x3c);
    }
}

