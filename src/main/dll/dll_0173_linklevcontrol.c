/* DLL 0x0173 (linklevcontrol) — Link level control object [0x801AF568-0x801AF9E4). */
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
#include "main/sky_interface.h"

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

extern void warpToMap(int mapId, int flags);

#define MEVT_TRIGGER(a, b, c) (*gMapEventInterface)->setObjGroupStatus((a), (b), (c))
#define MEVT_SET(a, b)        (*gMapEventInterface)->setMapAct((a), (b))

/* EN v1.0 0x801AC248  imicemountain_updateEventState: 8-state ice-mountain event machine dispatched
 * through jumptable_80323698 (states 1..7; state 0 idles). */
#undef MEVT_TRIGGER
#undef MEVT_SET

extern u8 lbl_802C2308[];

/* dll_16C_SeqFn: per-frame sequence callback - manage the spawned sub-object
 * from a small id table, then run the map-event sub-object state callbacks. */

/* dll_16C_syncSubObjectTransform: snapshot the map-event sub-object's transform into the boulder
 * extra block, optionally re-issuing a move on the sub-object first. */

extern void Music_Trigger(int track, int flag);
extern void SCGameBitLatch_Update(void* state, int mask, int a, int b, int c, int d);

/* imicemountain_update: lazy-spawn the ambient effects, run the active state,
 * fade the warning timer, drive the music latch, then refresh the gamebit latches. */

/* dll_16C_update: re-link the spawned sub-object, then while active/visible run
 * its move and fade opacity by distance to the player. */

extern u8 lbl_803236B8[];

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

extern undefined4 ObjHits_EnableObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80057690();
extern undefined8 FUN_80286830();
extern undefined4 FUN_8028687c();
extern void Music_Trigger(int id, int p2);
extern int getSaveGameLoadStatus(void);
extern void* Obj_GetPlayerObject(void);
extern int coordsToMapCell(f32 x, f32 z);
extern void SCGameBitLatch_Update(void* p, int a, int b, int c, int d, int e);
extern void fn_80088870(u8 * a, u8 * b, u8 * c, u8 * d);
extern void envFxActFn_800887f8(int id);
extern u8 lbl_803239F0[];
extern void ObjModel_SetBlendChannelTargets(int* model, int channel, int p3, int p4, f32 weight, int p6);
extern u8 lbl_803238D8[];
extern int ObjList_FindObjectById(int id);

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
    u8 savedByte;
    bool active;
    undefined2* obj;
    uint bit;
    int status;
    undefined4 flag;
    undefined2* subObj;
    undefined4* data;
    undefined8 ret;

    ret = FUN_80286830();
    obj = (undefined2*)((ulonglong)ret >> 0x20);
    if (obj[0x23] == 0x373)
    {
        FUN_8003b818((int)obj);
    }
    else
    {
        bit = GameBit_Get(0x6e);
        if ((bit == 0) || (bit = GameBit_Get(0x382), bit != 0))
        {
            data = *(undefined4**)(obj + 0x5c);
            subObj = (undefined2*)*data;
            active = false;
            if ((subObj != (undefined2*)0x0) &&
                (status = (**(code**)(**(int**)(subObj + 0x34) + 0x38))(subObj), status == 2))
            {
                active = true;
            }
            if (active)
            {
                obj[3] = obj[3] | 8;
                flag = FUN_80057690((int)subObj);
                param_6 = (char)flag;
                FUN_801adca0(obj, subObj, (int)ret, param_3, param_4, param_5, param_6,
                             (uint) * (byte*)(data + 8), 1);
            }
            else
            {
                obj[3] = obj[3] & ~0x8;
            }
            if ((param_6 != '\0') && (*(char*)(data + 8) != '\0'))
            {
                savedByte = *(u8*)((int)obj + 0x37);
                if (active)
                {
                    *(char*)((int)obj + 0x37) = *(char*)(data + 8);
                }
                FUN_8003b818((int)obj);
                ObjPath_GetPointWorldPosition(obj, 1, (float*)(data + 5), data + 6, (float*)(data + 7), 0);
                *(u8*)((int)obj + 0x37) = savedByte;
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

int link_levcontrol_getExtraSize(void) { return 0x10; }
int lavaball1bf_getExtraSize(void);

void imicepillar_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

#pragma scheduling off
#pragma peephole off
void link_levcontrol_free(int obj)
{
    switch ((s32)((GameObject*)obj)->anim.mapEventSlot)
    {
    case 0x45: Music_Trigger(0xda, 0);
        break;
    case 0x48:
    case 0x49: Music_Trigger(0x36, 0);
        break;
    }
}

void link_levcontrol_update(int* obj)
{
    LinkLevControlState* inner = ((GameObject*)obj)->extra;
    f32* player = (f32*)Obj_GetPlayerObject();
    if (player == NULL) return;

    if ((s32)inner->areaCell != (s32)((GameObject*)obj)->anim.mapEventSlot)
    {
        if ((s32)((GameObject*)obj)->anim.mapEventSlot == coordsToMapCell(player[3], player[5]))
        {
            link_levcontrol_applyEnterAreaEffects(obj);
        }
        else
        {
            return;
        }
    }
    if ((s32)((GameObject*)obj)->anim.mapEventSlot == coordsToMapCell(player[3], player[5]))
    {
        link_levcontrol_updateAreaMusic(obj);
    }
    inner->areaCell = (s8)coordsToMapCell(player[3], player[5]);
}

void link_levcontrol_updateAreaMusic(int* obj)
{
    LinkLevControlState* sub = ((GameObject*)obj)->extra;
    switch (((GameObject*)obj)->anim.mapEventSlot)
    {
    case 0x47:
        if ((*gSkyInterface)->getSunPosition(0) != 0)
        {
            if (sub->musicTrack != 0x2d)
            {
                sub->musicTrack = 0x2d;
                Music_Trigger(0x2d, 1);
            }
        }
        else
        {
            if (sub->musicTrack != 0x33)
            {
                sub->musicTrack = 0x33;
                Music_Trigger(0x33, 1);
            }
        }
        break;
    case 0x48:
        if (GameBit_Get(0xe1e) == 0)
        {
            if (GameBit_Get(0xb72) != 0)
            {
                if (sub->musicTrack != 0x95)
                {
                    sub->musicTrack = 0x95;
                    Music_Trigger(0x95, 1);
                }
            }
            else if ((*gSkyInterface)->getSunPosition(0) != 0)
            {
                if (sub->musicTrack != 0x2d)
                {
                    sub->musicTrack = 0x2d;
                    Music_Trigger(0x2d, 1);
                }
            }
            else
            {
                if (sub->musicTrack != 0x33)
                {
                    sub->musicTrack = 0x33;
                    Music_Trigger(0x33, 1);
                }
            }
        }
        SCGameBitLatch_Update(&sub->latch, 1, -1, -1, 0xe1e, 0x36);
        break;
    }
}

void link_levcontrol_applyEnterAreaEffects(int* obj)
{
    extern void getEnvfxAct(int a, int b, int c, int d); /* #57 */
    u8* tbl = lbl_803239F0;
    switch (((GameObject*)obj)->anim.mapEventSlot)
    {
    case 0x47:
        fn_80088870(tbl + 0x38, tbl, tbl + 0x70, tbl + 0xa8);
        if (((GameObject*)obj)->unkF4 == 2)
        {
            envFxActFn_800887f8(0x3f);
        }
        else
        {
            envFxActFn_800887f8(0x1f);
        }
        Music_Trigger(0xc2, 0);
        Music_Trigger(0xce, 0);
        Music_Trigger(0xcc, 0);
        Music_Trigger(0xdb, 0);
        Music_Trigger(0xf2, 0);
        break;
    case 0x45:
        skyFn_80088c94(7, 0);
        envFxActFn_800887f8(0);
        getEnvfxAct(0, 0, 0x13e, 0);
        getEnvfxAct(0, 0, 0x140, 0);
        getEnvfxAct(0, 0, 0x13f, 0);
        Music_Trigger(0xda, 1);
        break;
    case 0x49:
        Music_Trigger(0x36, 1);
        break;
    case 0x48:
        Music_Trigger(0xc8, 0);
        break;
    case 0x46:
        Music_Trigger(0xe1, 0);
        Music_Trigger(0x96, 1);
        break;
    }
}

void link_levcontrol_init(int* obj)
{
    LinkLevControlState* inner = ((GameObject*)obj)->extra;
    inner->areaCell = -1;
    inner->unk04 = -1;
    inner->musicTrack = -1;
    ((GameObject*)obj)->objectFlags |= 0x4000;
    if (getSaveGameLoadStatus() != 0)
    {
        ((GameObject*)obj)->unkF4 = 2;
    }
    else
    {
        ((GameObject*)obj)->unkF4 = 1;
    }
}
