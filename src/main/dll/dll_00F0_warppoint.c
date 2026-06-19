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
#include "main/game_object.h"
#include "main/dll/pushable.h"
#include "main/dll/dll_00EF_pushable.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/gamebits.h"

/* placement mapIds that arm the one-shot save-point recording at init */
#define WARPPOINT_MAP_SAVE_A 0x4B675
#define WARPPOINT_MAP_SAVE_B 0x46882

/* game bit shared with mode-0 markers to coordinate a single save point */
#define GAMEBIT_WARPPOINT_SAVED 0xD53

typedef struct WarpPointObjectDef
{
    u8 pad0[0x18 - 0x0];
    u8 pad18[0x20 - 0x18];
    s16 gameBit;
    u8 pad22[0x28 - 0x22];
} WarpPointObjectDef;

/* extra block; only the head 0x10 bytes are owned (WarpPoint_getExtraSize).
   state[0] (0x00) an s16 countdown timer, state[1] (0x02) a game bit,
   state[2] (0x04) a sequence id - all reached through the s16* alias. */
typedef struct WarpPointState
{
    u8 pad0[0x8 - 0x0];
    f32 triggerRadius;  /* 0x08 */
    u8 triggered;       /* 0x0C: sequence already fired this approach */
    u8 savePointRecorded; /* 0x0D: one-shot save-point latch */
    u8 padE[0x10 - 0xE];
} WarpPointState;


extern void warpToMap(int idx, s8 transType);
extern void* Obj_GetPlayerObject(void);

extern f32 sqrtf(f32 x);
extern u8 framesThisStep;
extern int getCurMapLayer(void);
extern f32 Vec_distance(f32* a, f32* b);
extern s16 lbl_803DCEB8;
extern u8 lbl_803DCDE0;
extern f32 lbl_803E35D8;
extern f32 lbl_803E35DC;

int WarpPoint_getExtraSize(void) { return 0x10; }
int WarpPoint_getObjectTypeId(void) { return 0x1; }

#pragma scheduling off
#pragma peephole off
void WarpPoint_render(int* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    int* p = *(int**)&((GameObject*)obj)->anim.placementData;
    if (visible == 0) return;
    if (*(s8*)((char*)p + 0x1d) == 1) return;
}
#pragma reset

int WarpPoint_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int* p = *(int**)&((GameObject*)obj)->anim.placementData;
    if (*(s8*)((char*)p + 0x1d) != 2)
    {
        if (animUpdate->triggerCommand == 1)
        {
            int v = (s8) * (u8*)((char*)p + 0x1a);
            if (v > -1)
            {
                warpToMap(v, 1);
                animUpdate->triggerCommand = 0;
            }
        }
    }
    return 0;
}

void WarpPoint_init(int* obj, u8* def)
{
    s16* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = WarpPoint_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)((u32)def[0x18] << 8);
    state[0] = 0x1e;
    ((WarpPointState*)state)->triggerRadius = (f32)((s32) * (s8*)((char*)def + 0x1e) << 2);
    state[1] = ((WarpPointObjectDef*)def)->gameBit;
    state[2] = (s16)(s32) * (s8*)((char*)def + 0x1b);
    if (*(s8*)((char*)def + 0x1c) != 0)
    {
        ((WarpPointState*)state)->triggered = 0;
    }
    else
    {
        ((WarpPointState*)state)->triggered = 1;
    }
    if (*(s8*)((char*)def + 0x1d) == 2)
    {
        state[0] = 0;
    }
    if (((ObjPlacement*)def)->mapId == WARPPOINT_MAP_SAVE_A || ((ObjPlacement*)def)->mapId == WARPPOINT_MAP_SAVE_B)
    {
        *(u8*)((char*)def + 0x1f) = 1;
    }
    else
    {
        *(u8*)((char*)def + 0x1f) = 0;
    }
}

void WarpPoint_update(int* obj)
{
    char* def;
    s16* state;
    char* player;
    f32 dist;

    def = *(char**)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    if (player == NULL)
    {
        return;
    }
    *state -= framesThisStep;
    if (*state < 0)
    {
        *state = 0;
    }
    if (*(u8*)(def + 0x1f) != 0 && ((WarpPointState*)state)->savePointRecorded == 0 && lbl_803DCEB8 > -1 &&
        lbl_803DCEB8 == *(s8*)(def + 0x19))
    {
        (*gMapEventInterface)->savePoint((int)(player + 0xc), ((GameObject*)player)->anim.rotX,
                                            0, getCurMapLayer());
        ((WarpPointState*)state)->savePointRecorded = 1;
    }
    switch (*(s8*)(def + 0x1d))
    {
    case 0:
        if (lbl_803DCEB8 > -1 || GameBit_Get(GAMEBIT_WARPPOINT_SAVED) != 0)
        {
            f32 dx = ((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
            f32 dy = ((PushableState*)player)->scale - ((GameObject*)obj)->anim.localPosY;
            f32 dz = ((PushableState*)player)->timer_0x14 - ((GameObject*)obj)->anim.localPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
            if (((WarpPointState*)state)->triggered == 0 && *(s8*)(def + 0x1c) != 0 &&
                dist < ((WarpPointState*)state)->triggerRadius &&
                *(u32*)&((GameObject*)player)->anim.parent == *(u32*)&((GameObject*)obj)->anim.parent)
            {
                if (((GameObject*)obj)->anim.seqId == 0x27e)
                {
                    GameBit_Set(GAMEBIT_WARPPOINT_SAVED, 1);
                    (*gMapEventInterface)->savePoint(
                        (int)(player + 0xc), ((GameObject*)player)->anim.rotX, 0, getCurMapLayer());
                }
                (*gObjectTriggerInterface)->runSequence(state[2], obj, -1);
                GameBit_Set(GAMEBIT_WARPPOINT_SAVED, 0);
                lbl_803DCDE0 = 2;
                ((WarpPointState*)state)->triggered = 1;
            }
        }
        if (*(s8*)(def + 0x1a) > -1)
        {
            f32 d2 = Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX);
            if (d2 < ((WarpPointState*)state)->triggerRadius)
            {
                warpToMap(*(s8*)(def + 0x1a), 1);
            }
        }
        break;
    case 1:
        {
            f32 dx = ((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
            f32 dy = ((PushableState*)player)->scale - ((GameObject*)obj)->anim.localPosY;
            f32 dz = ((PushableState*)player)->timer_0x14 - ((GameObject*)obj)->anim.localPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
            if (lbl_803DCEB8 > -1 && *(s8*)(def + 0x1c) != 0 && dist < lbl_803E35D8 &&
                *(u32*)&((GameObject*)player)->anim.parent == *(u32*)&((GameObject*)obj)->anim.parent)
            {
                (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                lbl_803DCDE0 = 2;
            }
            if (*state == 0 && dist < (f32) * (s8*)(def + 0x1e) && *(s8*)(def + 0x1a) > -1 &&
                *(s8*)(def + 0x1a) > -1)
            {
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
            }
            break;
        }
    case 2:
        if (lbl_803E35DC != (dist = ((WarpPointState*)state)->triggerRadius))
        {
            f32 dx = ((GameObject*)player)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
            f32 dy = ((PushableState*)player)->probeLocal[0].y - ((GameObject*)obj)->anim.worldPosY;
            f32 dz = ((PushableState*)player)->probeLocal[0].z - ((GameObject*)obj)->anim.worldPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
        }
        if (GameBit_Get(state[1]) != 0 && ((WarpPointState*)state)->triggered == 0 &&
            *(s8*)(def + 0x1c) != 0 && dist <= ((WarpPointState*)state)->triggerRadius &&
            *(u32*)&((GameObject*)player)->anim.parent == *(u32*)&((GameObject*)obj)->anim.parent)
        {
            (*gObjectTriggerInterface)->runSequence(state[2], obj, -1);
            ((WarpPointState*)state)->triggered = 1;
        }
        else
        {
            if (((WarpPointState*)state)->triggered == 1 && GameBit_Get(state[1]) != 0 && *state == 0 &&
                dist <= ((WarpPointState*)state)->triggerRadius && *(s8*)(def + 0x1a) > -1)
            {
                GameBit_Set(state[1], 0);
                warpToMap(*(s8*)(def + 0x1a), 0);
            }
        }
        break;
    case 3:
        {
            f32 dx = ((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
            f32 dy = ((PushableState*)player)->scale - ((GameObject*)obj)->anim.localPosY;
            f32 dz = ((PushableState*)player)->timer_0x14 - ((GameObject*)obj)->anim.localPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
            if (GameBit_Get(state[1]) != 0 && ((WarpPointState*)state)->triggered == 0 &&
                *(s8*)(def + 0x1c) != 0 && dist < ((WarpPointState*)state)->triggerRadius &&
                *(u32*)&((GameObject*)player)->anim.parent == *(u32*)&((GameObject*)obj)->anim.parent)
            {
                GameBit_Set(state[1], 0);
                (*gObjectTriggerInterface)->runSequence(state[2], obj, -1);
                ((WarpPointState*)state)->triggered = 1;
            }
            break;
        }
    case 4:
        if (lbl_803E35DC != (dist = ((WarpPointState*)state)->triggerRadius))
        {
            f32 dx = ((GameObject*)player)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
            f32 dy = ((PushableState*)player)->probeLocal[0].y - ((GameObject*)obj)->anim.worldPosY;
            f32 dz = ((PushableState*)player)->probeLocal[0].z - ((GameObject*)obj)->anim.worldPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
        }
        if (lbl_803DCEB8 > -1 && ((WarpPointState*)state)->triggered == 0 && *(s8*)(def + 0x1c) != 0 &&
            dist < ((WarpPointState*)state)->triggerRadius &&
            *(u32*)&((GameObject*)player)->anim.parent == *(u32*)&((GameObject*)obj)->anim.parent)
        {
            (*gObjectTriggerInterface)->runSequence(state[2], obj, -1);
            lbl_803DCDE0 = 2;
            ((WarpPointState*)state)->triggered = 1;
        }
        if (GameBit_Get(state[1]) != 0 && *state == 0 && dist <= ((WarpPointState*)state)->triggerRadius &&
            *(s8*)(def + 0x1a) > -1)
        {
            GameBit_Set(state[1], 0);
            warpToMap(*(s8*)(def + 0x1a), 1);
        }
        break;
    }
}
