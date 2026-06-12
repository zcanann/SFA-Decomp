/*
 * WM_LevelControl (DLL 0x209) - Krazoa Palace level control.
 * TU = 0x801F3F18..0x801F48C0 (helper fn_801F3F18 + wmlevelcontrol_*,
 * reverse slot order ascending).
 * fn_801F3F18 (the sky/light override helper called by update) is placed
 * LAST in this file so MWCC cannot inline it into wmlevelcontrol_update
 * (the target keeps it as an extern call).
 */
#include "main/dll/LGT/dll_0207_wmworm.h"
#include "main/dll/SC/SCtotemlogpuz.h"

typedef struct WmlevelcontrolState
{
    u8 pad0[0x4 - 0x0];
    s16 unk4;
    s16 unk6;
} WmlevelcontrolState;

extern undefined4 GameBit_Set(int eventId, int value);
extern void* Obj_GetPlayerObject(void);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShow(int textId);
extern uint GameBit_Get(int eventId);
extern int getCurSeqNo(void);

extern f64 DOUBLE_803e6b00;
extern f32 lbl_803E5E70;
extern f32 timeDelta;

#pragma scheduling on
#pragma peephole on
extern void ObjGroup_AddObject(int obj, int group);
extern int mapGetDirIdx(int mapId);
extern void unlockLevel(int a, int b, int c);
extern void lockLevel(int idx, int p2);
extern f32 lbl_803E5E90;
extern void setDrawLights(int mode);
extern int getSkyColorFn_80088e08(int slot);
extern void skySetOverrideLightColorEnabled(u8 enabled);
extern void skySetOverrideLightColor(u8 red, u8 green, u8 blue);
extern void skyFn_80089710(int flags, u32 enabled, int startComplete);
extern f32 fn_8008ED88(void);
extern void skyFn_800895e0(int flags, int red, int green, int blue, int m1, int m2);
extern void fn_80089510(int flags, int red, int green, int blue);
extern void fn_80089578(int flags, int red, int green, int blue);
extern void skySetOverrideLightDirectionEnabled(u8 enabled);
extern void skySetOverrideLightDirection(f32 x, f32 y, f32 z, f32 intensity);
extern void skyFn_800894a8(int flags, f32 x, f32 y, f32 z);
extern void ObjGroup_RemoveObject(int obj, int group);
extern void Music_Trigger(int musicId, int param);
extern f32 lbl_802C24B8[];
extern u8 lbl_803DC110;
extern u8 lbl_803DC114;
extern u8 lbl_803DC118;
extern u8 lbl_803DC11C;
extern u8 lbl_803DC120;
extern u8 lbl_803DC124;
extern f32 lbl_803DDC88;
extern f32 lbl_803DDC8C;
extern u8 lbl_803DDC90;
extern u8 lbl_803DDC94;
extern u8 lbl_803DDC98;
extern u8 lbl_803DDC9C;
extern f32 lbl_803E5E74;
extern f32 lbl_803E5E78;
extern f32 lbl_803E5E7C;
extern f32 lbl_803E5E80;
extern f32 lbl_803E5E84;
extern void objRenderFn_8003b8f4(f32);

void wmlevelcontrol_readParams(undefined2* param_1, int param_2)
{
    float* pfVar1;

    *param_1 = 0;
    pfVar1 = *(float**)(param_1 + 0x5c);
    *pfVar1 = (float)((double)CONCAT44(0x43300000, (int)*(char*)(param_2 + 0x18) << 2 ^ 0x80000000) -
        DOUBLE_803e6b00);
    *(undefined2*)(pfVar1 + 1) = *(undefined2*)(param_2 + 0x1a);
    *(undefined2*)(pfVar1 + 2) = *(undefined2*)(param_2 + 0x1c);
    *(undefined2*)(pfVar1 + 3) = 0;
    if (*(short*)(pfVar1 + 2) < 1)
    {
        *(int*)(param_1 + 0x7a) = (int)*(short*)(pfVar1 + 2);
    }
    else
    {
        *(undefined4*)(param_1 + 0x7a) = 0;
    }
    pfVar1[4] = *(float*)(param_1 + 6);
    pfVar1[5] = *(float*)(param_1 + 8);
    pfVar1[6] = *(float*)(param_1 + 10);
    return;
}

#pragma scheduling off
#pragma peephole off
void wmlevelcontrol_update(int obj)
{
    uint areaId;
    int loadingDone;
    float* state;
    float timer;

    Obj_GetPlayerObject();
    state = ((GameObject*)obj)->extra;
    timer = *state;
    if (timer > lbl_803E5E70)
    {
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        gameTextShow(0x42c);
        *state = *state - timeDelta;
        timer = *state;
        if (timer < lbl_803E5E70)
        {
            *state = *(f32*)&lbl_803E5E70;
        }
    }
    if (*(u8*)(state + 5) == 0)
    {
        areaId = (*gMapEventInterface)->getMode((int)((GameObject*)obj)->anim.mapEventSlot);
        areaId = __cntlzw(6 - (areaId & 0xff));
        areaId = areaId >> 5;
        if ((((int)areaId == 0) || (loadingDone = getCurSeqNo(), loadingDone == 0)) ||
            (areaId = GameBit_Get(0xa7f), areaId == 0))
        {
            SCGameBitLatch_UpdateInverted((SCGameBitLatchState*)(state + 4), 0x10, -1, -1, 0xa7f, 0xa6);
            SCGameBitLatch_Update((SCGameBitLatchState*)(state + 4), 2, -1, -1, 0xa7f, 0xa8);
        }
        if (0x3c < *(uint*)(state + 6))
        {
            SCGameBitLatch_Update((SCGameBitLatchState*)(state + 4), 1, -1, -1, 0xada, 0xac);
        }
        SCGameBitLatch_Update((SCGameBitLatchState*)(state + 4), 0x20, -1, -1, 0xcbb, 0xc4);
    }
    fn_801F3F18(obj);
    *(uint*)(state + 6) = *(uint*)(state + 6) + 1;
    return;
}

void wmlevelcontrol_init(int obj)
{
    f32* state;
    u8 mode;

    ObjGroup_AddObject(obj, 9);
    unlockLevel(mapGetDirIdx(0xb), 0, 0);
    state = ((GameObject*)obj)->extra;
    *((u8*)state + 0xb) = 0;
    ((WmlevelcontrolState*)state)->unk6 = 0x1e;
    *state = lbl_803E5E90;
    *(int*)(state + 4) = 0;
    lockLevel(0xf, 0);
    mode = (*gMapEventInterface)->getMode((int)((GameObject*)obj)->anim.mapEventSlot);
    switch (mode)
    {
    case 1:
        (*gMapEventInterface)->setMode(0xe, 1);
        (*gMapEventInterface)->setAnimEvent(0xe, 0, 1);
        break;
    case 2:
        GameBit_Set(0xd1b, 1);
        GameBit_Set(0xe6f, 1);
        GameBit_Set(0xf43, 1);
        GameBit_Set(0xf44, 0);
        break;
    case 3:
        GameBit_Set(0xd1b, 1);
        GameBit_Set(0xd1c, 1);
        GameBit_Set(0xa7f, 1);
        GameBit_Set(0xf43, 0);
        GameBit_Set(0xf44, 1);
        break;
    case 4:
        GameBit_Set(0xd1b, 1);
        GameBit_Set(0xd1c, 1);
        GameBit_Set(0xd1d, 1);
        GameBit_Set(0xa7f, 1);
        GameBit_Set(0xf43, 0);
        GameBit_Set(0xf44, 1);
        ((WmlevelcontrolState*)state)->unk4 = -1;
        break;
    case 5:
        GameBit_Set(0xd1b, 1);
        GameBit_Set(0xd1c, 1);
        GameBit_Set(0xd1d, 1);
        GameBit_Set(0xd1e, 1);
        GameBit_Set(0xf43, 0);
        GameBit_Set(0xf44, 1);
        break;
    case 6:
        GameBit_Set(0xd1b, 1);
        GameBit_Set(0xd1c, 1);
        GameBit_Set(0xd1d, 1);
        GameBit_Set(0xd1e, 1);
        GameBit_Set(0xd1f, 1);
        GameBit_Set(0x164, 1);
        GameBit_Set(0xf43, 0);
        GameBit_Set(0xf44, 0);
        break;
    case 7:
        *(s16*)(state + 2) = 700;
        *((u8*)state + 0xa) = 0x1e;
        ((WmlevelcontrolState*)state)->unk6 = *((u8*)state + 0xa);
        *((u8*)state + 0x14) = 1;
        break;
    }
}

void wmlevelcontrol_release(void)
{
}

void wmlevelcontrol_initialise(void)
{
}

/* Head of the TU (0x801F3F18..0x801F44B4), formerly the tail of
 * LGTdirectionallight.c. */

typedef struct
{
    f32 x, y, z;
} LightVec3;

typedef struct
{
    LightVec3 light;
    LightVec3 color;
    LightVec3 fog;
} LightVecSet;

int wmlevelcontrol_getExtraSize(void) { return 0x1c; }
int wmlevelcontrol_getObjectTypeId(void) { return 0x0; }

void wmlevelcontrol_free(int obj)
{
    ObjGroup_RemoveObject(obj, 9);
    Music_Trigger(0xa8, 0);
    GameBit_Set(0xa7f, 0);
    GameBit_Set(0x372, 1);
    GameBit_Set(0x390, 1);
}

void wmlevelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5E74);
}

void wmlevelcontrol_hitDetect(void)
{
}

/* Defined LAST so it cannot be auto-inlined into wmlevelcontrol_update
 * above (extern bl before the re-split; the retail unit keeps the bl). */
void fn_801F3F18(int obj)
{
    LightVecSet L;
    f32 lightX;
    LightVec3* vecs;
    u8* fromColor;
    u8* toColor;
    u8* outColor;

    vecs = (LightVec3*)lbl_802C24B8;
    L.fog = vecs[1];
    L.color = vecs[2];
    L.light = vecs[3];

    if ((u8)(*gMapEventInterface)->getMode(((GameObject*)obj)->anim.mapEventSlot) == 7)
    {
        return;
    }

    setDrawLights(0);
    if ((u8)getSkyColorFn_80088e08(0) != 0)
    {
        skySetOverrideLightColorEnabled(0);
        skySetOverrideLightDirectionEnabled(0);
        skyFn_80089710(7, 0, 1);
        return;
    }

    skySetOverrideLightColorEnabled(1);
    skySetOverrideLightColor(0x88, 0xb7, 0xba);
    if ((((GameObject*)obj)->unkF4 & 4) == 0)
    {
        skyFn_80089710(1, 1, 0);
        ((GameObject*)obj)->unkF4 |= 4;
    }
    else
    {
        skyFn_80089710(1, 1, 1);
    }

    if (fn_8008ED88() > 0.0f)
    {
        lbl_803DDC88 = lbl_803E5E74;
        lbl_803DDC8C = lbl_803E5E74;
    }
    lbl_803DDC8C = -(lbl_803E5E78 * timeDelta - lbl_803DDC8C);
    if (lbl_803DDC8C < 0.0f)
    {
        lbl_803DDC8C = 0.0f;
    }

    fromColor = &lbl_803DC118;
    toColor = &lbl_803DC11C;
    (&lbl_803DDC9C)[0] = lbl_803DDC8C * (f32)((s32)toColor[0] - (s32)fromColor[0]) +
                  (f32)(s32)fromColor[0];
    (&lbl_803DDC9C)[1] = lbl_803DDC8C * (f32)((s32)toColor[1] - (s32)fromColor[1]) +
                  (f32)(s32)fromColor[1];
    (&lbl_803DDC9C)[2] = lbl_803DDC8C * (f32)((s32)toColor[2] - (s32)fromColor[2]) +
                  (f32)(s32)fromColor[2];
    skyFn_800895e0(1, *(volatile u8*)&lbl_803DDC9C, ((volatile u8*)&lbl_803DDC9C)[1], ((volatile u8*)&lbl_803DDC9C)[2], 0x40, 0x40);

    fromColor = &lbl_803DC110;
    toColor = &lbl_803DC114;
    (&lbl_803DDC98)[0] = lbl_803DDC8C * (f32)((s32)toColor[0] - (s32)fromColor[0]) +
                  (f32)(s32)fromColor[0];
    (&lbl_803DDC98)[1] = lbl_803DDC8C * (f32)((s32)toColor[1] - (s32)fromColor[1]) +
                  (f32)(s32)fromColor[1];
    (&lbl_803DDC98)[2] = lbl_803DDC8C * (f32)((s32)toColor[2] - (s32)fromColor[2]) +
                  (f32)(s32)fromColor[2];
    fn_80089510(1, *(volatile u8*)&lbl_803DDC98, ((volatile u8*)&lbl_803DDC98)[1], ((volatile u8*)&lbl_803DDC98)[2]);

    fromColor = &lbl_803DC120;
    toColor = &lbl_803DC124;
    (&lbl_803DDC94)[0] = lbl_803DDC8C * (f32)((s32)toColor[0] - (s32)fromColor[0]) +
                  (f32)(s32)fromColor[0];
    (&lbl_803DDC94)[1] = lbl_803DDC8C * (f32)((s32)toColor[1] - (s32)fromColor[1]) +
                  (f32)(s32)fromColor[1];
    (&lbl_803DDC94)[2] = lbl_803DDC8C * (f32)((s32)toColor[2] - (s32)fromColor[2]) +
                  (f32)(s32)fromColor[2];
    fn_80089578(1, *(volatile u8*)&lbl_803DDC94, ((volatile u8*)&lbl_803DDC94)[1], ((volatile u8*)&lbl_803DDC94)[2]);

    lbl_803DDC90 = lbl_803DDC8C * lbl_803E5E80 + lbl_803E5E7C;
    skySetOverrideLightDirectionEnabled(1);
    skySetOverrideLightDirection(lbl_803DDC8C * (L.light.x - (lightX = L.color.x)) + lightX,
                                 lbl_803DDC8C * (L.light.y - L.color.y) + L.color.y,
                                 lbl_803DDC8C * (L.light.z - L.color.z) + L.color.z,
                                 lbl_803E5E84);
    skyFn_800894a8(1, L.fog.x, L.fog.y, L.fog.z);
}
