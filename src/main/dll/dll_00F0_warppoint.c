/*
 * warppoint (DLL 0x00F0) - placed map-transition / save-point markers.
 *
 * Each instance carries a placement-defined "mode" byte (def+0x1d) that
 * selects how the marker behaves in WarpPoint_update:
 *   mode 0: proximity warp / trigger-sequence near the player;
 *   mode 1: trigger sequences while a hint flag is set and on a timer;
 *   mode 2/4: gated warp when its game bit is set and the player is in
 *             range (modes 2/4 use the world-space distance variant);
 *   mode 3: one-shot trigger-sequence gated on its game bit.
 * mode 2 also doubles as a no-op marker at init (clears the timer).
 *
 * Most behavior keys off the player object's position/parent, the global
 * map-hint byte (lbl_803DCEB8), and per-marker game bits. Markers placed
 * on the WARPPOINT_MAP_SAVE_* maps additionally record a save point the
 * first time the matching hint byte is seen.
 *
 * The shared sequence/particle helpers for the pushable/transporter object
 * family (pushable, invhit, iceblast, flameblast) live in the dll_00EF
 * pushable TU in the same binary; they are not called from this object.
 */
#include "main/obj_placement.h"
#include "main/rcp_dolphin_api.h"
#include "main/game_object.h"
#include "main/dll/pushable.h"
#include "main/dll/dll_00EF_pushable.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/dll/DR/dr_shared.h"

typedef struct WarpPointObjectDef
{
    ObjPlacement head; /* 0x00: common placement head (color / pos / mapId) */
    u8 rotByte;        /* 0x18: initial yaw, shifted into anim.rotX */
    s8 hintId;         /* 0x19: map-hint id matched against lbl_803DCEB8 */
    s8 warpMapIdx;     /* 0x1a: destination map index for warpToMap */
    s8 seqId;          /* 0x1b: sequence id cached into WarpPointState.seqId */
    s8 enableFlag;     /* 0x1c: nonzero arms the trigger */
    s8 mode;           /* 0x1d: behavior selector (0..4) */
    s8 radiusByte;     /* 0x1e: trigger radius seed */
    u8 savePointArmed; /* 0x1f: one-shot save-point arming flag */
    s16 gameBit;       /* 0x20 */
    u8 pad22[0x28 - 0x22];
} WarpPointObjectDef;

STATIC_ASSERT(offsetof(WarpPointObjectDef, mode) == 0x1d);
STATIC_ASSERT(offsetof(WarpPointObjectDef, gameBit) == 0x20);

/* extra block; only the head 0x10 bytes are owned (WarpPoint_getExtraSize). */
typedef struct WarpPointState
{
    s16 countdown;
    s16 gameBit;
    s16 seqId;
    s16 unk06;
    f32 triggerRadius;    /* 0x08 */
    u8 triggered;         /* 0x0C: sequence already fired this approach */
    u8 savePointRecorded; /* 0x0D: one-shot save-point latch */
    u8 padE[0x10 - 0xE];
} WarpPointState;

/* placement mapIds that arm the one-shot save-point recording at init */
#define WARPPOINT_MAP_SAVE_A 0x4B675
#define WARPPOINT_MAP_SAVE_B 0x46882

/* seqId variant that records a save point (sets GAMEBIT_WARPPOINT_SAVED
   and calls the map-event savePoint) before running its sequence. */
#define WARPPOINT_SEQID_SAVEPOINT 0x27e

/* def->mode behavior selector (see file header) */
#define WARPPOINT_MODE_PROXIMITY   0 /* proximity warp / trigger-sequence near player */
#define WARPPOINT_MODE_HINT_TIMER  1 /* trigger while hint flag set, on a timer */
#define WARPPOINT_MODE_GATED_WARP  2 /* game-bit-gated warp, world-space distance */
#define WARPPOINT_MODE_ONESHOT_SEQ 3 /* one-shot trigger-sequence gated on game bit */
#define WARPPOINT_MODE_GATED_WARP2 4 /* game-bit-gated warp variant, world-space distance */

/* game bit shared with mode-0 markers to coordinate a single save point */
#define GAMEBIT_WARPPOINT_SAVED 0xD53

extern s16 lbl_803DCEB8;
extern u8 lbl_803DCDE0;


#pragma scheduling off
#pragma peephole off
int WarpPoint_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    WarpPointObjectDef* p = *(WarpPointObjectDef**)&((GameObject*)obj)->anim.placementData;
    if (p->mode != WARPPOINT_MODE_GATED_WARP)
    {
        if (animUpdate->triggerCommand == 1)
        {
            int v = (s8) * (u8*)&p->warpMapIdx;
            if (v > -1)
            {
                warpToMap(v, 1);
                animUpdate->triggerCommand = 0;
            }
        }
    }
    return 0;
}

int WarpPoint_getExtraSize(void)
{
    return 0x10;
}
int WarpPoint_getObjectTypeId(void)
{
    return 0x1;
}

void WarpPoint_render(int* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    WarpPointObjectDef* p = *(WarpPointObjectDef**)&((GameObject*)obj)->anim.placementData;
    if (visible == 0)
        return;
    if (p->mode == WARPPOINT_MODE_HINT_TIMER)
        return;
}
#pragma reset

void WarpPoint_update(GameObject* obj)
{
    WarpPointObjectDef* def;
    WarpPointState* state;
    GameObject* player;
    f32 dist;

    def = (WarpPointObjectDef*)obj->anim.placementData;
    state = obj->extra;
    player = Obj_GetPlayerObject();
    if (player == NULL)
    {
        return;
    }
    state->countdown -= framesThisStep;
    if (state->countdown < 0)
    {
        state->countdown = 0;
    }
    if (def->savePointArmed != 0 && state->savePointRecorded == 0 && lbl_803DCEB8 > -1 &&
        lbl_803DCEB8 == def->hintId)
    {
        (*gMapEventInterface)->savePoint((int)&player->anim.localPosX, player->anim.rotX, 0, getCurMapLayer());
        state->savePointRecorded = 1;
    }
    switch (def->mode)
    {
    case WARPPOINT_MODE_PROXIMITY:
        if (lbl_803DCEB8 > -1 || mainGetBit(GAMEBIT_WARPPOINT_SAVED) != 0)
        {
            f32 dx = player->anim.localPosX - obj->anim.localPosX;
            f32 dy = player->anim.localPosY - obj->anim.localPosY;
            f32 dz = player->anim.localPosZ - obj->anim.localPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
            if (state->triggered == 0 && def->enableFlag != 0 && dist < state->triggerRadius &&
                *(u32*)&player->anim.parent == *(u32*)&obj->anim.parent)
            {
                if (obj->anim.seqId == WARPPOINT_SEQID_SAVEPOINT)
                {
                    mainSetBits(GAMEBIT_WARPPOINT_SAVED, 1);
                    (*gMapEventInterface)
                        ->savePoint((int)&player->anim.localPosX, player->anim.rotX, 0, getCurMapLayer());
                }
                (*gObjectTriggerInterface)->runSequence(state->seqId, obj, -1);
                mainSetBits(GAMEBIT_WARPPOINT_SAVED, 0);
                lbl_803DCDE0 = 2;
                state->triggered = 1;
            }
        }
        if (def->warpMapIdx > -1)
        {
            f32 d2 = Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX);
            if (d2 < state->triggerRadius)
            {
                warpToMap(def->warpMapIdx, 1);
            }
        }
        break;
    case WARPPOINT_MODE_HINT_TIMER:
    {
        f32 dx = player->anim.localPosX - obj->anim.localPosX;
        f32 dy = player->anim.localPosY - obj->anim.localPosY;
        f32 dz = player->anim.localPosZ - obj->anim.localPosZ;
        dist = sqrtf(dx * dx + dy * dy + dz * dz);
        if (lbl_803DCEB8 > -1 && def->enableFlag != 0 && dist < 100.0f &&
            *(u32*)&player->anim.parent == *(u32*)&obj->anim.parent)
        {
            (*gObjectTriggerInterface)->runSequence(1, obj, -1);
            lbl_803DCDE0 = 2;
        }
        if (state->countdown == 0 && dist < (f32)def->radiusByte && def->warpMapIdx > -1 &&
            def->warpMapIdx > -1)
        {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
        break;
    }
    case WARPPOINT_MODE_GATED_WARP:
        if (0.0f != (dist = state->triggerRadius))
        {
            f32 dx = player->anim.worldPosX - obj->anim.worldPosX;
            f32 dy = player->anim.worldPosY - obj->anim.worldPosY;
            f32 dz = player->anim.worldPosZ - obj->anim.worldPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
        }
        if (mainGetBit(state->gameBit) != 0 && state->triggered == 0 && def->enableFlag != 0 &&
            dist <= state->triggerRadius && *(u32*)&player->anim.parent == *(u32*)&obj->anim.parent)
        {
            (*gObjectTriggerInterface)->runSequence(state->seqId, obj, -1);
            state->triggered = 1;
        }
        else
        {
            if (state->triggered == 1 && mainGetBit(state->gameBit) != 0 && state->countdown == 0 &&
                dist <= state->triggerRadius && def->warpMapIdx > -1)
            {
                mainSetBits(state->gameBit, 0);
                warpToMap(def->warpMapIdx, 0);
            }
        }
        break;
    case WARPPOINT_MODE_ONESHOT_SEQ:
    {
        f32 dx = player->anim.localPosX - obj->anim.localPosX;
        f32 dy = player->anim.localPosY - obj->anim.localPosY;
        f32 dz = player->anim.localPosZ - obj->anim.localPosZ;
        dist = sqrtf(dx * dx + dy * dy + dz * dz);
        if (mainGetBit(state->gameBit) != 0 && state->triggered == 0 && def->enableFlag != 0 &&
            dist < state->triggerRadius && *(u32*)&player->anim.parent == *(u32*)&obj->anim.parent)
        {
            mainSetBits(state->gameBit, 0);
            (*gObjectTriggerInterface)->runSequence(state->seqId, obj, -1);
            state->triggered = 1;
        }
        break;
    }
    case WARPPOINT_MODE_GATED_WARP2:
        if (0.0f != (dist = state->triggerRadius))
        {
            f32 dx = player->anim.worldPosX - obj->anim.worldPosX;
            f32 dy = player->anim.worldPosY - obj->anim.worldPosY;
            f32 dz = player->anim.worldPosZ - obj->anim.worldPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
        }
        if (lbl_803DCEB8 > -1 && state->triggered == 0 && def->enableFlag != 0 && dist < state->triggerRadius &&
            *(u32*)&player->anim.parent == *(u32*)&obj->anim.parent)
        {
            (*gObjectTriggerInterface)->runSequence(state->seqId, obj, -1);
            lbl_803DCDE0 = 2;
            state->triggered = 1;
        }
        if (mainGetBit(state->gameBit) != 0 && state->countdown == 0 && dist <= state->triggerRadius &&
            def->warpMapIdx > -1)
        {
            mainSetBits(state->gameBit, 0);
            warpToMap(def->warpMapIdx, 1);
        }
        break;
    }
}

void WarpPoint_init(GameObject* obj, WarpPointObjectDef* def)
{
    WarpPointState* state = obj->extra;
    obj->animEventCallback = WarpPoint_SeqFn;
    obj->anim.rotX = (s16)((u32)def->rotByte << 8);
    state->countdown = 0x1e;
    state->triggerRadius = (f32)((s32)def->radiusByte << 2);
    state->gameBit = def->gameBit;
    state->seqId = (s16)(s32)def->seqId;
    if (def->enableFlag != 0)
    {
        state->triggered = 0;
    }
    else
    {
        state->triggered = 1;
    }
    if (def->mode == WARPPOINT_MODE_GATED_WARP)
    {
        state->countdown = 0;
    }
    if (def->head.mapId == WARPPOINT_MAP_SAVE_A || def->head.mapId == WARPPOINT_MAP_SAVE_B)
    {
        def->savePointArmed = 1;
    }
    else
    {
        def->savePointArmed = 0;
    }
}
