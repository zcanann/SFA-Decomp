/* DLL 0x016E (imanimspacecraft) - IM animated spacecraft object [0x801AE144-0x801AE508). */
#include "main/dll/linklevcontrolstate_struct.h"
#include "main/dll/lavaball1bfstate_struct.h"
#include "main/dll/imspacethrusterstate_struct.h"
#include "main/dll/lavaball1bestate_struct.h"
#include "main/dll/imanimspacecraftstate_struct.h"
#include "main/dll/dll16cstate_struct.h"
#include "main/dll/magiclightstate_struct.h"
#include "main/dll/crrockfall_types.h"
#include "main/objtexture.h"

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

#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIMcannon.h"

STATIC_ASSERT(sizeof(ImAnimSpacecraftState) == 0x4);

STATIC_ASSERT(sizeof(ImSpaceThrusterState) == 0xC);

STATIC_ASSERT(sizeof(LinkLevControlState) == 0x10);

STATIC_ASSERT(sizeof(Lavaball1beState) == 0x14);

STATIC_ASSERT(sizeof(Lavaball1bfState) == 0x1C);

extern undefined4 FUN_8003b818();
extern undefined4 FUN_80057690();
extern undefined8 FUN_80286830();
extern undefined4 FUN_8028687c();
extern f32 lbl_803E4784;
extern char lbl_803AC948[];
extern f32 lbl_803E4780;
extern f32 lbl_803E4788;
extern void Music_Trigger(int id, int p2);
extern f32 lbl_803E47A8, lbl_803E47AC, lbl_803E47B0, lbl_803E47B4, lbl_803E4798, lbl_803E4788;
extern f32 lbl_803E4770, lbl_803E4774, lbl_803E4778, lbl_803E477C;
extern f32 lbl_803E478C, lbl_803E4790, lbl_803E4794, lbl_803E4798;

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
    u8 savedAlpha;
    bool active;
    undefined2* obj;
    uint bit;
    int subState;
    undefined4 alpha;
    undefined2* subObj;
    undefined4* placement;
    undefined8 packed;

    packed = FUN_80286830();
    obj = (undefined2*)((ulonglong)packed >> 0x20);
    if (obj[0x23] == 0x373)
    {
        FUN_8003b818((int)obj);
    }
    else
    {
        bit = GameBit_Get(0x6e);
        if ((bit == 0) || (bit = GameBit_Get(0x382), bit != 0))
        {
            placement = *(undefined4**)(obj + 0x5c);
            subObj = (undefined2*)*placement;
            active = false;
            if ((subObj != (undefined2*)0x0) &&
                (subState = (**(code**)(**(int**)(subObj + 0x34) + 0x38))(subObj), subState == 2))
            {
                active = true;
            }
            if (active)
            {
                obj[3] = obj[3] | 8;
                alpha = FUN_80057690((int)subObj);
                param_6 = (char)alpha;
                FUN_801adca0(obj, subObj, (int)packed, param_3, param_4, param_5, param_6,
                             (uint) * (byte*)(placement + 8), 1);
            }
            else
            {
                obj[3] = obj[3] & ~0x8;
            }
            if ((param_6 != '\0') && (*(char*)(placement + 8) != '\0'))
            {
                savedAlpha = *(u8*)((int)obj + 0x37);
                if (active)
                {
                    *(char*)((int)obj + 0x37) = *(char*)(placement + 8);
                }
                FUN_8003b818((int)obj);
                ObjPath_GetPointWorldPosition(obj, 1, (float*)(placement + 5), placement + 6, (float*)(placement + 7), 0);
                *(u8*)((int)obj + 0x37) = savedAlpha;
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

int imanimspacecraft_getExtraSize(void) { return 0x4; }
int imanimspacecraft_getObjectTypeId(void) { return 0x0; }
int imspacethruster_getExtraSize(void);

void imanimspacecraft_update(int* obj)
{
    if (((GameObject*)obj)->unkF4 != 0) return;
    ((GameObject*)obj)->unkF4 = 1;
}

void imanimspacecraft_free(int* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

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

void lavaball1bf_func11(int* obj);

void imicepillar_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void imanimspacecraft_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4780);
}

void imspacethruster_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

u32 imanimspacecraft_func0B(int* obj) { return *((u8*)((int**)obj)[0xb8 / 4] + 0x3) & 0x4; }
u32 lavaball1be_func11(int* obj);

int imanimspacecraft_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    ImAnimSpacecraftState* state;
    int i;
    ObjTextureRuntimeSlot* tex;

    state = ((GameObject*)obj)->extra;
    tex = objFindTexture(obj, 1, 0);
    tex->textureId = ((state->flags >> 1 & 1) ^ 1) << 8;
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
    tex->textureId = 0x100;
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
