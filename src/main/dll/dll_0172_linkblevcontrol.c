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

/* dll_16C_SeqFn: per-frame sequence callback - manage the spawned sub-object
 * from a small id table, then run the map-event sub-object state callbacks. */

/* dll_16C_syncSubObjectTransform: snapshot the map-event sub-object's transform into the boulder
 * extra block, optionally re-issuing a move on the sub-object first. */

extern void Music_Trigger(int track, int flag);
extern void SCGameBitLatch_Update(void* state, int mask, int a, int b, int c, int d);
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

extern undefined4 FUN_8003b818();
extern undefined4 FUN_80057690();
extern undefined8 FUN_80286830();
extern undefined4 FUN_8028687c();
extern void Music_Trigger(int id, int p2);
extern int getSaveGameLoadStatus(void);
extern void* Obj_GetPlayerObject(void);
extern void SCGameBitLatch_Update(void* p, int a, int b, int c, int d, int e);
extern void fn_80088870(u8 * a, u8 * b, u8 * c, u8 * d);
extern void envFxActFn_800887f8(int id);
extern u8 lbl_803238D8[];
extern void getEnvfxActImmediately(int a, int b, int c, int d);
extern int* getTrickyObject(void);
extern void fn_80138908(int* tricky, int mode);
extern f32 lbl_803E47C8;

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

int linkb_levcontrol_getExtraSize(void) { return 0x10; }
int link_levcontrol_getExtraSize(void);

void imicepillar_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

typedef struct
{
    int flags;
    s8 cnt : 2;
    u8 stage : 3;
    u8 low : 3;
    u8 flag5 : 1;
    u8 pad5 : 7;
    u8 pad6[2];
    f32 timer;
    s16 music;
} LinkbLevState;

#pragma scheduling off
#pragma peephole off
void linkb_levcontrol_init(int* obj)
{
    extern void getEnvfxAct(int a, int b, int c, int d); /* #57 */
    u8* t = (u8*)(int)lbl_803238D8;
    LinkbLevState* sub = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
    if (GameBit_Get(0x36e) != 0)
    {
        sub->flags &= 4;
    }
    if (GameBit_Get(0x543) != 0)
    {
        sub->stage = 5;
    }
    else if (GameBit_Get(0x387) != 0)
    {
        sub->stage = 4;
    }
    else if (GameBit_Get(0x386) != 0)
    {
        sub->stage = 3;
    }
    else if (GameBit_Get(0x385) != 0)
    {
        sub->stage = 2;
    }
    else if (GameBit_Get(0x384) != 0)
    {
        sub->stage = 1;
    }
    fn_80088870(t + 0x38, (u8*)(int)lbl_803238D8, t + 0x70, t + 0xa8);
    if (getSaveGameLoadStatus() != 0)
    {
        if ((u8)(*gMapEventInterface)->getObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0) == 0)
        {
            envFxActFn_800887f8(0x3f);
        }
        getEnvfxActImmediately(0, 0, 0x23c, 0);
    }
    else
    {
        if ((u8)(*gMapEventInterface)->getObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0) == 0)
        {
            envFxActFn_800887f8(0x1f);
        }
        getEnvfxAct(0, 0, 0x23c, 0);
    }
    sub->music = 0;
}

void linkb_levcontrol_update(int* obj)
{
    extern undefined4 GameBit_Set(int eventId, int value); /* #57 */
    LinkbLevState* state;
    int* tricky;
    int* player;
    u8* cur;

    state = ((GameObject*)obj)->extra;
    player = (int*)Obj_GetPlayerObject();
    tricky = getTrickyObject();
    cur = (*gMapEventInterface)->getTrickyEnergy();
    if ((*gSkyInterface)->getSunPosition(0) != 0)
    {
        if (state->music != -1)
        {
            state->music = -1;
            if (state->flags & 8)
            {
                Music_Trigger(0x1a, 0);
            }
        }
    }
    else
    {
        if (state->music != 0x1a)
        {
            state->music = 0x1a;
            if (state->flags & 8)
            {
                Music_Trigger(0x1a, 1);
            }
        }
    }
    SCGameBitLatch_Update(state, 1, -1, -1, 0x3a0, 0x35);
    SCGameBitLatch_Update(state, 2, -1, -1, 0xb36, 0x96);
    SCGameBitLatch_Update(state, 8, -1, -1, 0x3a1, state->music);
    if (state->flags & 4)
    {
        if (GameBit_Get(0x1fd) == 0 && GameBit_Get(0x256) == 0)
        {
            GameBit_Set(0x36e, 0);
            state->flags &= ~4;
        }
    }
    else
    {
        if (GameBit_Get(0x256) != 0 || GameBit_Get(0x1fd) != 0)
        {
            GameBit_Set(0x36e, 1);
            state->flags |= 4;
        }
    }
    if (tricky != NULL)
    {
        fn_80138908(tricky, 0);
        switch (state->stage)
        {
        case 0:
            if (GameBit_Get(0x384) != 0)
            {
                fn_80138908(tricky, 1);
                (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                state->stage++;
                state->low = 0;
                return;
            }
            break;
        case 1:
            if (GameBit_Get(0xc1) != 0)
            {
                if (!(((GameObject*)player)->objectFlags & 0x1000))
                {
                    GameBit_Set(0x385, 1);
                    fn_80138908(tricky, 1);
                    (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                    state->stage++;
                    state->low = 0;
                    return;
                }
            }
            break;
        case 2:
            if (cur[0] != 0)
            {
                fn_80138908(tricky, 1);
                if (state->cnt-- == -1 && !(((GameObject*)tricky)->objectFlags & 0x1000))
                {
                    GameBit_Set(0x386, 1);
                    (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                    state->stage++;
                    state->low = 0;
                    return;
                }
            }
            break;
        case 3:
            if (GameBit_Get(0x1fd) != 0)
            {
                GameBit_Set(0x387, 1);
                state->stage++;
                break;
            }
            if (GameBit_Get(0x380) != 0)
            {
                state->flag5 = 1;
                break;
            }
            if (state->flag5 != 0)
            {
                GameBit_Set(0x387, 1);
                fn_80138908(tricky, 1);
                (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                state->stage++;
                state->low = 0;
                return;
            }
            break;
        case 4:
            if (GameBit_Get(0x543) != 0)
            {
                fn_80138908(tricky, 1);
                (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                state->stage++;
                state->low = 0;
                return;
            }
            break;
        }
    }
    if (tricky != NULL)
    {
        if (!(((GameObject*)tricky)->objectFlags & 0x1000))
        {
            state->timer = state->timer + timeDelta;
        }
        if (GameBit_Get(0x4e3) == 1 && cur[0] >= 4)
        {
            GameBit_Set(0x4e3, 0xff);
        }
        if (state->timer >= lbl_803E47C8)
        {
            state->timer = state->timer - lbl_803E47C8;
            if (GameBit_Get(0x4e3) == 0xff && cur[0] < 4)
            {
                GameBit_Set(0x4e3, 1);
            }
        }
    }
}
