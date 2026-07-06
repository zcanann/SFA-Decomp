/*
 * wallanimator (DLL 0x13B) - a crumbling/animating wall object that
 * "completes" once its internal timer reaches WALLANIMATOR_DONE_TIMER.
 * On completion it sets the runtime active bit, grants its placement
 * game bit (placement+0x18) and plays the completion sfx. While running
 * it tracks the nearest Tricky object (group WALLANIMATOR_NEARBY_GROUP)
 * and toggles its own hitbox-mode bits accordingly. setScale spawns the
 * wall's debris/dust particle bursts and derives a render scale from the
 * distance to a target object.
 *
 * The object joins ObjGroup WALLANIMATOR_GROUP_PRIMARY/SECONDARY at init
 * and leaves them at free. This TU is a fragment of the MMP wallanimator
 * DLL (shares MMP/dll_013B_wallanimator.h with its sibling TUs, which
 * also house the wave/alpha/ground/vis animator state - hence the
 * layout STATIC_ASSERTs below).
 */
#include "main/dll/groundanimator_state.h"
#include "main/dll/waveanimatorstate_struct.h"
#include "main/dll/alphaanimatorstate_struct.h"
#include "main/dll/visanimatorstate_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/MMP/dll_013B_wallanimator.h"
#include "main/gamebits.h"
#include "main/objlib.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/sfx.h"

STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);
STATIC_ASSERT(sizeof(AlphaAnimatorState) == 0x1C);
STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);
STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);


extern void objRenderFn_80041018(int obj);
extern int getTrickyObject(void);

#define TRICKY_IFACE_OFFSET 0x68    /* tricky object -> interface vtable pointer */
#define TRICKY_IFACE_NOTIFY_SLOT 0x28 /* vtable slot invoked when in range */

/* placement record: only the +0x1C short (debris spawn roll) is read here */
typedef struct WallanimatorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 gameBit;
    u8 pad1A[0x1C - 0x1A];
    s16 spawnRotZ; /* 0x1C: debris spawn rotation (rot[2]) / modelMtx selector */
    u8 pad1E[0x24 - 0x1E];
    s16 initialRotX; /* 0x24: initial rotX seed */
    u8 pad26[0x28 - 0x26];
} WallanimatorPlacement;

/* per-object extra state: 0x00 s32 timer; 0x04 bit 0x80 (activeFlag) = completed */
typedef struct WallanimatorState
{
    s32 timer;
    u8 activeFlag : 1;
    u8 unk4Rest : 7;
    u8 pad5[0x8 - 0x5];
} WallanimatorState;

STATIC_ASSERT(sizeof(WallanimatorState) == 8);

u8 wallanimator_modelMtxFn(int* obj)
{
    return (u8)((WallanimatorPlacement*)(((GameObject*)obj)->anim.placementData))->spawnRotZ;
}

u8 wallanimator_func0B(int* obj)
{
    WallanimatorState* state = ((GameObject*)obj)->extra;
    return state->timer >= WALLANIMATOR_DONE_TIMER;
}

f32 wallanimator_setScale(int obj, int target)
{
    struct
    {
        s16 rot[3];
        char pad[6];
        f32 pos[3];
    } spawn;
    f32 deltaX;
    f32 deltaY;
    f32 deltaZ;
    f32 offset[3];
    int placementDesc;
    int count;
    WallanimatorState* state;
    f32 scale;

    placementDesc = *(int*)&((GameObject*)obj)->anim.placementData;
    count = 6;
    do
    {
        offset[0] = 0.13f * (f32)(int)randomGetRange(-0x64, 0x64);
        offset[1] = 0.0f;
        offset[2] = 0.0f;
        spawn.rot[2] = randomGetRange(-0x7fff, 0x8000);
        spawn.rot[1] = 0;
        spawn.rot[0] = 0;
        vecRotateZXY(spawn.rot, offset);
        offset[2] -= 25.0f;
        vecRotateZXY((void*)obj, offset);
        spawn.rot[2] = ((WallanimatorPlacement*)placementDesc)->spawnRotZ;
        spawn.rot[0] = ((GameObject*)obj)->anim.rotX;
        spawn.pos[0] = ((GameObject*)obj)->anim.worldPosX + offset[0];
        spawn.pos[1] = 15.0f + (((GameObject*)obj)->anim.worldPosY + offset[1]);
        spawn.pos[2] = ((GameObject*)obj)->anim.worldPosZ + offset[2];
        (*gPartfxInterface)->spawnObject((void*)obj, 0xca, spawn.rot, 0x200001, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, 0xcb, spawn.rot, 0x200001, -1, NULL);
        count--;
    }
    while (count != 0);

    state = ((GameObject*)obj)->extra;
    deltaY = ((GameObject*)target)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
    if ((deltaY < -20.0f) || (deltaY > 20.0f))
    {
        scale = 0.0f;
    }
    else
    {
        deltaX = ((GameObject*)target)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
        deltaZ = ((GameObject*)target)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
        if (deltaX * deltaX + deltaZ * deltaZ > 2500.0f)
        {
            scale = 0.0f;
        }
        else
        {
            state->timer += 0x3c;
            scale = state->timer / 3000.0f;
        }
    }
    return scale;
}

int wallanimator_getExtraSize(void)
{
    return sizeof(WallanimatorState);
}

void wallanimator_free(int obj)
{
    ObjGroup_RemoveObject(obj, WALLANIMATOR_GROUP_PRIMARY);
    ObjGroup_RemoveObject(obj, WALLANIMATOR_GROUP_SECONDARY);
}

void wallanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
}

void wallanimator_update(int obj)
{
    int nearby;
    WallanimatorState* state;
    int desc;
    int tricky;
    float nearestDistance[4];

    state = ((GameObject*)obj)->extra;
    desc = *(int*)&((GameObject*)obj)->anim.placementData;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED;

    if (state->activeFlag != 0)
    {
        return;
    }

    if (state->timer >= WALLANIMATOR_DONE_TIMER)
    {
        state->activeFlag = 1;
        GameBit_Set((int)((WallanimatorPlacement*)desc)->gameBit, 1);
        Sfx_PlayFromObject(obj, WALLANIMATOR_COMPLETE_SFX);
        return;
    }

    tricky = getTrickyObject();
    if ((void*)tricky != NULL)
    {
        nearestDistance[0] = 35.0f;
        nearby = ObjGroup_FindNearestObject(WALLANIMATOR_NEARBY_GROUP, obj, nearestDistance);
        if ((void*)nearby == NULL)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_PROMPT_SUPPRESSED;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED;
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0)
            {
                (*(void (**)(int, int, int, int))(**(int**)(tricky + TRICKY_IFACE_OFFSET) + TRICKY_IFACE_NOTIFY_SLOT))(tricky, obj, 1, 1);
            }
            objRenderFn_80041018(obj);
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_PROMPT_SUPPRESSED;
    }
}

#pragma optimization_level 1
#pragma peephole on
void wallanimator_init(s16* obj, s16* placement)
{
    int oi;
    WallanimatorState* state;
    GameObject* go;

    go = (GameObject*)obj;
    oi = (int)obj;
    state = go->extra;
    *obj = ((WallanimatorPlacement*)placement)->initialRotX;
    ObjGroup_AddObject(oi, WALLANIMATOR_GROUP_PRIMARY);
    ObjGroup_AddObject((int)obj, WALLANIMATOR_GROUP_SECONDARY);
    if (GameBit_Get((int)((WallanimatorPlacement*)placement)->gameBit) != 0)
    {
        state->activeFlag = 1;
        state->timer = WALLANIMATOR_DONE_TIMER;
    }
}
#pragma peephole reset
#pragma optimization_level reset
