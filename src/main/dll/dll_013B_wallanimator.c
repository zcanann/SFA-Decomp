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

STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);
STATIC_ASSERT(sizeof(AlphaAnimatorState) == 0x1C);
STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);
STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);

extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern int ObjGroup_FindNearestObject();
extern void ObjGroup_RemoveObject(int obj, int group);
extern void ObjGroup_AddObject(int obj, int group);

extern void objRenderFn_8003b8f4(f32);
extern void vecRotateZXY(void* in, void* out);
extern u32 randomGetRange(int min, int max);

extern f32 lbl_803E4C98; /* default coord fallback */
extern f32 lbl_803E3FFC; /* nearest-object search radius seed */
extern f32 lbl_803E3FD0;
extern f32 lbl_803E3FD4;
extern f32 lbl_803E3FD8;
extern f32 lbl_803E3FDC;
extern f32 lbl_803E3FE0; /* deltaY lower bound */
extern f32 lbl_803E3FE4; /* deltaY upper bound */
extern f32 lbl_803E3FE8; /* max planar distance squared */
extern f32 lbl_803E3FEC; /* scale divisor */
extern f32 lbl_803E3FF8; /* render scale */

/* placement record: only the +0x1C short (debris spawn roll) is read here */
typedef struct WallanimatorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 gameBit;
    u8 pad1A[0x1C - 0x1A];
    s16 unk1C;
    u8 pad1E[0x24 - 0x1E];
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} WallanimatorPlacement;

/* per-object extra state: 0x00 s32 timer; 0x04 bit 0x80 (activeFlag) = completed */
typedef struct WallanimatorState
{
    u8 pad0[0x4 - 0x0];
    u8 activeFlag : 1;
    u8 unk4Rest : 7;
    u8 pad5[0x8 - 0x5];
} WallanimatorState;

STATIC_ASSERT(sizeof(WallanimatorState) == 8);

u8 wallanimator_func0B(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    return *state >= WALLANIMATOR_DONE_TIMER;
}

u8 wallanimator_modelMtxFn(int* obj)
{
    return (u8)((WallanimatorPlacement*)(((GameObject*)obj)->anim.placementData))->unk1C;
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
    int desc;
    int count;
    int* state;
    f32 scale;
    f32 riseY;
    f32 dropZ;
    f32 baseSpread;
    f32 jitterX;

    desc = *(int*)&((GameObject*)obj)->anim.placementData;
    count = 6;
    do
    {
        jitterX = lbl_803E3FD0;
        baseSpread = lbl_803E3FD4;
        dropZ = lbl_803E3FD8;
        riseY = lbl_803E3FDC;
        offset[0] = jitterX * (f32)(int)randomGetRange(-0x64, 0x64);
        offset[1] = baseSpread;
        offset[2] = baseSpread;
        spawn.rot[2] = (s16)randomGetRange(-0x7fff, 0x8000);
        spawn.rot[1] = 0;
        spawn.rot[0] = 0;
        vecRotateZXY(spawn.rot, offset);
        offset[2] -= dropZ;
        vecRotateZXY((void*)obj, offset);
        spawn.rot[2] = ((WallanimatorPlacement*)desc)->unk1C;
        spawn.rot[0] = ((GameObject*)obj)->anim.rotX;
        spawn.pos[0] = ((GameObject*)obj)->anim.worldPosX + offset[0];
        spawn.pos[1] = riseY + (((GameObject*)obj)->anim.worldPosY + offset[1]);
        spawn.pos[2] = ((GameObject*)obj)->anim.worldPosZ + offset[2];
        (*gPartfxInterface)->spawnObject((void*)obj, 0xca, spawn.rot, 0x200001, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, 0xcb, spawn.rot, 0x200001, -1, NULL);
        count--;
    }
    while (count != 0);

    state = ((GameObject*)obj)->extra;
    deltaY = ((GameObject*)target)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
    if ((deltaY < lbl_803E3FE0) || (deltaY > lbl_803E3FE4))
    {
        scale = lbl_803E3FD4;
    }
    else
    {
        deltaX = ((GameObject*)target)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
        deltaZ = ((GameObject*)target)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
        if (deltaX * deltaX + deltaZ * deltaZ > lbl_803E3FE8)
        {
            scale = lbl_803E3FD4;
        }
        else
        {
            *state += 0x3c;
            scale = (f32) * state / lbl_803E3FEC;
        }
    }
    return scale;
}

/* coordinate getter (objFn_801948c0): coord selects a world/local axis
 * read out of the object's accumulator floats at extra+0x40/0x44/0x48. */
double FUN_80194a70(int obj, u8 coord)
{
    int state;

    if ((obj == 0) || (state = *(int*)&((GameObject*)obj)->extra, state == 0))
    {
        return (double)lbl_803E4C98;
    }
    if (coord == 4)
    {
        return (double)*(float*)(state + 0x44);
    }
    if (coord < 4)
    {
        if (coord == 2)
        {
            return (double)*(float*)(state + 0x40);
        }
        if (1 < coord)
        {
            return (double)(((GameObject*)obj)->anim.localPosY + *(float*)(state + 0x44));
        }
        if (coord != 0)
        {
            return (double)(((GameObject*)obj)->anim.localPosX + *(float*)(state + 0x40));
        }
    }
    else
    {
        if (coord == 6)
        {
            return (double)*(float*)(state + 0x48);
        }
        if (coord < 6)
        {
            return (double)(((GameObject*)obj)->anim.localPosZ + *(float*)(state + 0x48));
        }
    }
    return (double)lbl_803E4C98;
}

int wallanimator_getExtraSize(void)
{
    return sizeof(WallanimatorState);
}

void wallanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3FF8);
}

void wallanimator_free(int obj)
{
    ObjGroup_RemoveObject(obj, WALLANIMATOR_GROUP_PRIMARY);
    ObjGroup_RemoveObject(obj, WALLANIMATOR_GROUP_SECONDARY);
}

void wallanimator_update(int obj)
{
    extern void objRenderFn_80041018(int obj);
    extern int getTrickyObject(void);
    extern void Sfx_PlayFromObject(int obj, int sfxId);
    int nearby;
    int* state;
    int desc;
    int tricky;
    float nearestDistance[4];

    state = ((GameObject*)obj)->extra;
    desc = *(int*)&((GameObject*)obj)->anim.placementData;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8;

    if (((*(u8*)(state + 1) >> 7) & 1) != 0u)
    {
        return;
    }

    if (*state >= WALLANIMATOR_DONE_TIMER)
    {
        ((WallanimatorState*)state)->activeFlag = 1;
        GameBit_Set((int)((WallanimatorPlacement*)desc)->gameBit, 1);
        Sfx_PlayFromObject(obj, WALLANIMATOR_COMPLETE_SFX);
        return;
    }

    tricky = getTrickyObject();
    if ((void*)tricky != NULL)
    {
        nearestDistance[0] = lbl_803E3FFC;
        nearby = ObjGroup_FindNearestObject(WALLANIMATOR_NEARBY_GROUP, obj, nearestDistance);
        if ((void*)nearby == NULL)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x10;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~8;
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
            {
                (*(void (**)(int, int, int, int))(**(int**)(tricky + 0x68) + 0x28))(tricky, obj, 1, 1);
            }
            objRenderFn_80041018(obj);
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x10;
    }
}

void wallanimator_init(s16* obj, s16* placement)
{
    int* state;

    state = ((GameObject*)obj)->extra;
    *obj = (s16)((WallanimatorPlacement*)placement)->unk24;
    ObjGroup_AddObject((int)obj, WALLANIMATOR_GROUP_PRIMARY);
    ObjGroup_AddObject((int)obj, WALLANIMATOR_GROUP_SECONDARY);
    if (GameBit_Get((int)((WallanimatorPlacement*)placement)->gameBit) != 0)
    {
        ((WallanimatorState*)state)->activeFlag = 1;
        *state = WALLANIMATOR_DONE_TIMER;
    }
}
