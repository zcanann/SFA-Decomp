/*
 * WM_LevelControl (DLL 0x209) - Krazoa Palace level control.
 * TU = 0x801F3F18..0x801F48C0 (helper fn_801F3F18 + wmlevelcontrol_*,
 * reverse slot order ascending).
 *
 * init seeds the palace's game-bit progression from the map-event mode
 * (the 0xD1B..0xD1F spirit chain consumed by wmspiritplace and
 * friends); update shows the intro message while messageTimer runs,
 * drives the music game-bit latches, and calls the sky/light override
 * helper every frame. fn_801F3F18 cross-fades the palace's sky, light
 * and fog colors toward their spirit-restored values while the
 * lbl_803DDC8C blend factor (held at 1.0 during restore progress,
 * decaying 0.02/tick after) is up.
 */
#include "main/dll/WM/dll_0207_wmworm.h"
#include "main/dll/SC/SCtotemlogpuz.h"
#include "main/objlib.h"

/* per-object extra state (getExtraSize == 0x1C) */
typedef struct WmLevelControlState
{
    f32 messageTimer;          /* 0x00: intro-message frames left */
    s16 unk04;                 /* 0x04: -1 at map-event mode 4, else unset */
    s16 unk06;                 /* 0x06 */
    s16 unk08;                 /* 0x08: 700 at mode 7, else unset */
    u8 unk0A;                  /* 0x0A: 0x1E at mode 7, else unset */
    u8 unk0B;                  /* 0x0B: cleared at init, never read */
    u8 pad0C[4];
    SCGameBitLatchState latch; /* 0x10: music-trigger latches */
    u8 latchesDisabled;        /* 0x14: set at mode 7; skips all latching */
    u8 pad15[3];
    u32 frameCounter;          /* 0x18: frames since init */
} WmLevelControlState;

STATIC_ASSERT(offsetof(WmLevelControlState, unk08) == 0x08);
STATIC_ASSERT(offsetof(WmLevelControlState, latch) == 0x10);
STATIC_ASSERT(offsetof(WmLevelControlState, latchesDisabled) == 0x14);
STATIC_ASSERT(offsetof(WmLevelControlState, frameCounter) == 0x18);
STATIC_ASSERT(sizeof(WmLevelControlState) == 0x1C);

extern void GameBit_Set(int eventId, int value);
extern void* Obj_GetPlayerObject(void);
extern void gameTextSetColor(u8 r, u8 g, u8 b, u8 a);
extern void gameTextShow(int a);
extern u32 GameBit_Get(int eventId);
extern int getCurSeqNo(void);

extern f32 lbl_803E5E70; /* 0.0 */
extern f32 timeDelta;

extern int mapGetDirIdx(int mapId);
extern int unlockLevel(s32 val, int idx, int flag);
extern void lockLevel(int idx, int p2);
extern f32 lbl_803E5E90; /* 300.0: intro-message duration */
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
extern void Music_Trigger(int id, int arg);
extern f32 lbl_802C24B8[]; /* sky light/color/fog vector table */
extern u8 lbl_803DC110;    /* sky-color blend source triplet */
extern u8 lbl_803DC114;    /* sky-color blend target triplet */
extern u8 lbl_803DC118;    /* light-color blend source triplet */
extern u8 lbl_803DC11C;    /* light-color blend target triplet */
extern u8 lbl_803DC120;    /* fog-color blend source triplet */
extern u8 lbl_803DC124;    /* fog-color blend target triplet */
extern f32 lbl_803DDC88;   /* restore-blend hold flag */
extern f32 lbl_803DDC8C;   /* current blend factor */
extern u8 lbl_803DDC90;    /* blended light-intensity byte */
extern u8 lbl_803DDC94;    /* blended fog-color out-triplet */
extern u8 lbl_803DDC98;    /* blended sky-color out-triplet */
extern u8 lbl_803DDC9C;    /* blended light-color out-triplet */
extern f32 lbl_803E5E74;   /* 1.0 */
extern f32 lbl_803E5E78;   /* 0.02: blend decay per tick */
extern f32 lbl_803E5E7C;   /* 32.0: light-intensity base */
extern f32 lbl_803E5E80;   /* 128.0: light-intensity blend range */
extern f32 lbl_803E5E84;   /* 100.0: override light intensity */
extern void objRenderFn_8003b8f4(f32);

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

/* Defined before update like retail (TU head); too large for MWCC's
 * auto-inliner, so update keeps the bl (stream-verified). */
void fn_801F3F18(int obj)
{
    LightVecSet L;
    f32 lightX;
    f32 decay;
    LightVec3* vecs;
    u8* fromColor;
    u8* toColor;

    vecs = (LightVec3*)lbl_802C24B8;
    L.fog = vecs[1];
    L.color = vecs[2];
    L.light = vecs[3];

    if ((u8)(*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot) == 7)
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

    /* hold the blend at full while spirit-restore progress is running,
       then decay it toward 0. The volatile launders re-load the zero
       per use (#114; a plain extern CSEs into a reg, a literal would
       pool locally and block the unit's sdata2 claim). */
    if (fn_8008ED88() > *(volatile f32*)&lbl_803E5E70)
    {
        lbl_803DDC88 = lbl_803E5E74;
        lbl_803DDC8C = lbl_803E5E74;
    }
    decay = -(lbl_803E5E78 * timeDelta - lbl_803DDC8C);
    lbl_803DDC8C = decay;
    if (decay < (lightX = *(volatile f32*)&lbl_803E5E70))
    {
        lbl_803DDC8C = lightX;
    }

    /* blend each color channel source->target by the blend factor.
       The call args re-read the just-stored bytes VOLATILE (#114):
       MWCC's word-granular store forwarding otherwise passes the last
       byte stored for all three args - the misforward this fn shipped
       with before the volatile reads. */
    fromColor = &lbl_803DC118;
    toColor = &lbl_803DC11C;
    (&lbl_803DDC9C)[0] = lbl_803DDC8C * (f32)((s32)toColor[0] - fromColor[0]) +
                  (f32)(s32)fromColor[0];
    (&lbl_803DDC9C)[1] = lbl_803DDC8C * (f32)((s32)toColor[1] - fromColor[1]) +
                  (f32)(s32)fromColor[1];
    (&lbl_803DDC9C)[2] = lbl_803DDC8C * (f32)((s32)toColor[2] - fromColor[2]) +
                  (f32)(s32)fromColor[2];
    skyFn_800895e0(1, *(volatile u8*)&lbl_803DDC9C, ((volatile u8*)&lbl_803DDC9C)[1], ((volatile u8*)&lbl_803DDC9C)[2], 0x40, 0x40);

    fromColor = &lbl_803DC110;
    toColor = &lbl_803DC114;
    (&lbl_803DDC98)[0] = lbl_803DDC8C * (f32)((s32)toColor[0] - fromColor[0]) +
                  (f32)(s32)fromColor[0];
    (&lbl_803DDC98)[1] = lbl_803DDC8C * (f32)((s32)toColor[1] - fromColor[1]) +
                  (f32)(s32)fromColor[1];
    (&lbl_803DDC98)[2] = lbl_803DDC8C * (f32)((s32)toColor[2] - fromColor[2]) +
                  (f32)(s32)fromColor[2];
    fn_80089510(1, *(volatile u8*)&lbl_803DDC98, ((volatile u8*)&lbl_803DDC98)[1], ((volatile u8*)&lbl_803DDC98)[2]);

    fromColor = &lbl_803DC120;
    toColor = &lbl_803DC124;
    (&lbl_803DDC94)[0] = lbl_803DDC8C * (f32)((s32)toColor[0] - fromColor[0]) +
                  (f32)(s32)fromColor[0];
    (&lbl_803DDC94)[1] = lbl_803DDC8C * (f32)((s32)toColor[1] - fromColor[1]) +
                  (f32)(s32)fromColor[1];
    (&lbl_803DDC94)[2] = lbl_803DDC8C * (f32)((s32)toColor[2] - fromColor[2]) +
                  (f32)(s32)fromColor[2];
    fn_80089578(1, *(volatile u8*)&lbl_803DDC94, ((volatile u8*)&lbl_803DDC94)[1], ((volatile u8*)&lbl_803DDC94)[2]);

    lbl_803DDC90 = lbl_803DDC8C * lbl_803E5E80 + lbl_803E5E7C;
    skySetOverrideLightDirectionEnabled(1);
    /* the embedded def pins light.x-then-color.x load order in the
       x arg (the bare spelling pre-hoists the two-use color.x) */
    skySetOverrideLightDirection(lbl_803DDC8C * (L.light.x - (lightX = L.color.x)) + lightX,
                                 lbl_803DDC8C * (L.light.y - L.color.y) + L.color.y,
                                 lbl_803DDC8C * (L.light.z - L.color.z) + L.color.z,
                                 lbl_803E5E84);
    skyFn_800894a8(1, L.fog.x, L.fog.y, L.fog.z);
}

int wmlevelcontrol_getExtraSize(void) { return sizeof(WmLevelControlState); }
int wmlevelcontrol_getObjectTypeId(void) { return 0x0; }

void wmlevelcontrol_free(int obj)
{
    ObjGroup_RemoveObject((u32)obj, 9);
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

void wmlevelcontrol_update(int obj)
{
    u32 mode6;
    int loadingDone;
    WmLevelControlState* state;
    float timer;

    Obj_GetPlayerObject(); /* result unused (retail does the same call) */
    state = ((GameObject*)obj)->extra;
    timer = state->messageTimer;
    if (timer > lbl_803E5E70)
    {
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        gameTextShow(0x42c);
        state->messageTimer = state->messageTimer - timeDelta;
        timer = state->messageTimer;
        if (timer < lbl_803E5E70)
        {
            state->messageTimer = *(f32*)&lbl_803E5E70;
        }
    }
    if (state->latchesDisabled == 0)
    {
        mode6 = (*gMapEventInterface)->getMapAct((int)((GameObject*)obj)->anim.mapEventSlot);
        mode6 = __cntlzw(6 - (mode6 & 0xff));
        mode6 = mode6 >> 5;
        if ((((int)mode6 == 0) || (loadingDone = getCurSeqNo(), loadingDone == 0)) ||
            (mode6 = GameBit_Get(0xa7f), mode6 == 0))
        {
            SCGameBitLatch_UpdateInverted(&state->latch, 0x10, -1, -1, 0xa7f, 0xa6);
            SCGameBitLatch_Update(&state->latch, 2, -1, -1, 0xa7f, 0xa8);
        }
        if (0x3c < state->frameCounter)
        {
            SCGameBitLatch_Update(&state->latch, 1, -1, -1, 0xada, 0xac);
        }
        SCGameBitLatch_Update(&state->latch, 0x20, -1, -1, 0xcbb, 0xc4);
    }
    fn_801F3F18(obj);
    state->frameCounter = state->frameCounter + 1;
    return;
}

void wmlevelcontrol_init(int obj)
{
    WmLevelControlState* state;
    u8 mode;

    ObjGroup_AddObject((u32)obj, 9);
    unlockLevel(mapGetDirIdx(0xb), 0, 0);
    state = ((GameObject*)obj)->extra;
    state->unk0B = 0;
    state->unk06 = 0x1e;
    state->messageTimer = lbl_803E5E90;
    state->latch.activeMask = 0;
    lockLevel(0xf, 0);
    /* the 0xD1B..0xD1F chain marks how many Krazoa spirits the palace
       has received (wmspiritplace's progression); 0xF43/0xF44 pick the
       ambience variant. All cross-TU bits without established names. */
    mode = (*gMapEventInterface)->getMapAct((int)((GameObject*)obj)->anim.mapEventSlot);
    switch (mode)
    {
    case 1:
        (*gMapEventInterface)->setMapAct(0xe, 1);
        (*gMapEventInterface)->setObjGroupStatus(0xe, 0, 1);
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
        state->unk04 = -1;
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
        state->unk08 = 700;
        state->unk0A = 0x1e;
        state->unk06 = state->unk0A;
        state->latchesDisabled = 1;
        break;
    }
}

void wmlevelcontrol_release(void)
{
}

void wmlevelcontrol_initialise(void)
{
}
