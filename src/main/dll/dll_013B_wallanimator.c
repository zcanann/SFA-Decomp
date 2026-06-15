#include "main/dll/groundanimator_state.h"
#include "main/dll/waveanimatorstate_struct.h"
#include "main/dll/alphaanimatorstate_struct.h"
#include "main/dll/visanimatorstate_struct.h"
#include "main/dll/MMP/mmp_barrel.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/MMP/dll_013B_wallanimator.h"

/* waveanimator_getExtraSize == 0x3c (also the shared wave-grid config fed
 * to fn_801923F8; the grid/color/phase tables live in the lbl_803DDAEC/F0/F4
 * globals). */

STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);

STATIC_ASSERT(sizeof(AlphaAnimatorState) == 0x1C);

STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);

STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern int ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();

extern void mm_free(void* p);
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E3F98;
extern void vecRotateZXY(void* in, void* out);
extern u32 randomGetRange(int min, int max);
extern void mm_free(void* ptr);
extern f32 lbl_803E4C98;
extern f32 lbl_803E3FFC;
extern f32 lbl_803E3FD0;
extern f32 lbl_803E3FD4;
extern f32 lbl_803E3FD8;
extern f32 lbl_803E3FDC;
extern f32 lbl_803E3FE0;
extern f32 lbl_803E3FE4;
extern f32 lbl_803E3FE8;
extern f32 lbl_803E3FEC;
extern f32 lbl_803E3FF8;

u8 wallanimator_func0B(int* obj)
{
    int* p = ((int**)obj)[0xb8 / 4];
    return *p >= WALLANIMATOR_DONE_TIMER;
}

u8 wallanimator_modelMtxFn(int* obj) { return (u8) * (s16*)((char*)((int**)obj)[0x4c / 4] + 0x1c); }

/* segment pragma-stack balance (re-split): */

typedef struct WallanimatorPlacement
{
    u8 pad0[0x1C - 0x0];
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
} WallanimatorPlacement;

typedef struct WallanimatorState
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 pad5[0x8 - 0x5];
} WallanimatorState;

typedef struct WallanimatorActiveBits
{
    u8 active : 1;
    u8 rest : 7;
} WallanimatorActiveBits;

f32 wallanimator_setScale(int obj, int target)
{
    struct
    {
        s16 rot[3];
        char pad[6];
        f32 pos[3];
    } effect;
    f32 deltaX;
    f32 deltaY;
    f32 deltaZ;
    f32 out[3];
    int desc;
    int count;
    int* state;
    f32 scale;
    f32 kD0;
    f32 kD4;
    f32 kD8;
    f32 kDC;

    desc = *(int*)&((GameObject*)obj)->anim.placementData;
    count = 6;
    kD0 = lbl_803E3FD0;
    kD4 = lbl_803E3FD4;
    kD8 = lbl_803E3FD8;
    kDC = lbl_803E3FDC;
    do
    {
        out[0] = kD0 * (f32)(int)
        randomGetRange(-0x64, 0x64);
        out[1] = kD4;
        out[2] = kD4;
        effect.rot[2] = (s16)randomGetRange(-0x7fff, 0x8000);
        effect.rot[1] = 0;
        effect.rot[0] = 0;
        vecRotateZXY(effect.rot, out);
        out[2] -= kD8;
        vecRotateZXY((void*)obj, out);
        effect.rot[2] = ((WallanimatorPlacement*)desc)->unk1C;
        effect.rot[0] = *(s16*)obj;
        effect.pos[0] = ((GameObject*)obj)->anim.worldPosX + out[0];
        effect.pos[1] = kDC + (((GameObject*)obj)->anim.worldPosY + out[1]);
        effect.pos[2] = ((GameObject*)obj)->anim.worldPosZ + out[2];
        (*gPartfxInterface)->spawnObject((void*)obj, 0xca, effect.rot, 0x200001, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, 0xcb, effect.rot, 0x200001, -1, NULL);
        count--;
    }
    while (count != 0);

    state = ((GameObject*)obj)->extra;
    deltaY = ((GameObject*)target)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
    if ((lbl_803E3FE0 > deltaY) || (lbl_803E3FE4 < deltaY))
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

double FUN_80194a70(int param_1, byte param_2)
{
    int iVar1;

    if ((param_1 == 0) || (iVar1 = *(int*)&((GameObject*)param_1)->extra, iVar1 == 0))
    {
        return (double)lbl_803E4C98;
    }
    if (param_2 == 4)
    {
        return (double)*(float*)(iVar1 + 0x44);
    }
    if (param_2 < 4)
    {
        if (param_2 == 2)
        {
            return (double)*(float*)(iVar1 + 0x40);
        }
        if (1 < param_2)
        {
            return (double)(((GameObject*)param_1)->anim.localPosY + *(float*)(iVar1 + 0x44));
        }
        if (param_2 != 0)
        {
            return (double)(((GameObject*)param_1)->anim.localPosX + *(float*)(iVar1 + 0x40));
        }
    }
    else
    {
        if (param_2 == 6)
        {
            return (double)*(float*)(iVar1 + 0x48);
        }
        if (param_2 < 6)
        {
            return (double)(((GameObject*)param_1)->anim.localPosZ + *(float*)(iVar1 + 0x48));
        }
    }
    return (double)lbl_803E4C98;
}

int wallanimator_getExtraSize(void)
{
    return 8;
}

void wallanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3FF8);
}

void xyzanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void wallanimator_free(int obj)
{
    ObjGroup_RemoveObject(obj, WALLANIMATOR_GROUP_PRIMARY);
    ObjGroup_RemoveObject(obj, WALLANIMATOR_GROUP_SECONDARY);
}

void wallanimator_update(int obj)
{
    extern void objRenderFn_80041018(int obj); /* #57 */
    extern int getTrickyObject(void); /* #57 */
    extern void Sfx_PlayFromObject(int obj, int sfxId); /* #57 */
    int nearby;
    int* state;
    int desc;
    int tricky;
    float nearestDistance[4];

    state = ((GameObject*)obj)->extra;
    desc = *(int*)&((GameObject*)obj)->anim.placementData;
    *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.resetHitboxMode | 8;

    if (((*(u8*)(state + 1) >> 7) & 1) != 0u)
    {
        return;
    }

    if (*state >= WALLANIMATOR_DONE_TIMER)
    {
        ((WallanimatorActiveBits*)((u8*)state + 4))->active = 1;
        GameBit_Set((int)*(short*)(desc + 0x18), 1);
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
            *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.resetHitboxMode & ~
                0x10;
            *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.resetHitboxMode & ~8;
            if ((*(byte*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
            {
                (*(code*)(**(int**)(tricky + 0x68) + 0x28))(tricky, obj, 1, 1);
            }
            objRenderFn_80041018(obj);
        }
    }
    else
    {
        *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.resetHitboxMode | 0x10;
    }
}

void wallanimator_init(s16* obj, s16* p2)
{
    register int* state = ((GameObject*)obj)->extra;

    *obj = (s16)p2[0x24 / 2];
    ObjGroup_AddObject((int)obj, WALLANIMATOR_GROUP_PRIMARY);
    ObjGroup_AddObject((int)obj, WALLANIMATOR_GROUP_SECONDARY);
    if (GameBit_Get((int)p2[0x18 / 2]) != 0)
    {
        ((WallanimatorState*)state)->unk4 |= WALLANIMATOR_RUNTIME_ACTIVE_FLAG;
        *state = WALLANIMATOR_DONE_TIMER;
    }
}
