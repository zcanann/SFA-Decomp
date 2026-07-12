/*
 * cflevelcontrol (DLL 0x164) - the CloudRunner Fortress level
 * controller. init clears the fortress bit set on a fresh visit and
 * arms the one-shot object sweep; update advances the fortress map
 * event, stings/fanfares the two alarm bits, runs the first-visit and
 * post-flood environment setups, tracks the disguise and cell-camera
 * bits, and drives the music latches. The SeqFn handles the level-exit
 * event (flood the fortress and lock the map).
 */
#include "main/audio/sfx_ids.h"
#include "main/object_api.h"
#include "main/render.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera_interface.h"
#include "main/dll/alphaanim.h"
#include "main/mapEvent.h"
#include "main/game_object.h"
#include "main/sky_api.h"
#include "main/gamebits.h"
#include "main/gamebit_ids.h"
#include "main/audio/sfx.h"
#include "main/dll/fx_800944A0_shared.h"

typedef struct CflevelcontrolState
{
    u8 pad0[0x8 - 0x0];
    s32 unk8;
    u8 padC[0xD - 0xC];
    s8 unkD;
    u8 padE[0x10 - 0xE];
} CflevelcontrolState;

typedef struct CfTriggerPos
{
    int x, y, z;
} CfTriggerPos;

typedef struct CfLevelControlFlags
{
    u8 b7 : 1;
    u8 b6 : 1;
    u8 b5 : 1; /* 0x20: last GameBit 0x974 */
    u8 b4 : 1; /* 0x10: last GameBit 0x975 */
    u8 b3 : 1; /* 0x08: pending objCallOnloadCallback sweep */
    u8 rest : 3;
} CfLevelControlFlags;

#define CFLEVELCONTROL_OBJFLAG_PARENT_SLACK 0x1000

/* env-effect ids activated on first update tick: ENVFX_A is always-on; B/C/D
   are the day-preset set (bit 0xd73), B/E/F the night-preset set (bit 0xdca) */
#define CFLEVELCONTROL_ENVFX_A 0x56
#define CFLEVELCONTROL_ENVFX_B 0xd
#define CFLEVELCONTROL_ENVFX_C 0x11
#define CFLEVELCONTROL_ENVFX_D 0xe
#define CFLEVELCONTROL_ENVFX_E 0x7e
#define CFLEVELCONTROL_ENVFX_F 0x7d

/* CloudRunner Fortress map-event id advanced by the level controller (getMapAct/setMapAct) */
#define CFLEVELCONTROL_MAP_FORTRESS 0x1d

extern s16 lbl_80323008[];
extern f32 lbl_803E43E8;
extern int lbl_802C22E8[];
extern f32 lbl_803E43EC;

extern void s16toFloat(void* p, int duration);
extern void storeZeroToFloatParam(void* p);
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern int unlockLevel(s32 val, int idx, int flag);
extern int playerIsDisguised(int obj);
extern void staffToggle(GameObject* obj, int a);
extern int getCurMapLayer(void);
extern void SCGameBitLatch_Update(void* latch, int mask, int clearIfSetBit, int clearIfClearBit, int latchBit,
                                  int musicId);
extern void SCGameBitLatch_UpdateInverted(void* latch, int mask, int clearIfSetBit, int clearIfClearBit, int latchBit,
                                          int musicId);
extern int loadMapAndParent(int mapId);
extern int mapGetDirIdx(int idx);
extern int lockLevel(s32 val, int idx);
extern void objSetSlot(u8* obj, s8 slot);

int CFLevelControl_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        int v = animUpdate->eventIds[i];
        switch (v)
        {
        case 1:
            mainSetBits(GAMEBIT_CFRaceRelated0DCB, 1);
            mainSetBits(GAMEBIT_CF_ObjGroups2, 0);
            loadMapAndParent(0x2b);
            unlockLevel(0, 0, 1);
            lockLevel(mapGetDirIdx(0x2b), 0);
            break;
        }
    }
    return 0;
}

int cflevelcontrol_getExtraSize(void)
{
    return 0x10;
}

int cflevelcontrol_getObjectTypeId(void)
{
    return 0x0;
}

void cflevelcontrol_free(int obj)
{
}

void cflevelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E43E8);
}

void cflevelcontrol_hitDetect(void)
{
}

void cflevelcontrol_update(GameObject* obj)
{
    u8* state = obj->extra;
    int player = (int)Obj_GetPlayerObject();
    CfTriggerPos triggerPos;
    u32 bit974;
    u8 bit975;
    int bit94e;
    int cameraMode;

    triggerPos = *(CfTriggerPos*)lbl_802C22E8;

    if (((u32)state[0xc] >> 3 & 1) != 0)
    {
        objCallOnloadCallback((int*)ObjList_FindObjectById(0x47fae));
        objCallOnloadCallback((int*)ObjList_FindObjectById(0x47f83));
        objCallOnloadCallback((int*)ObjList_FindObjectById(0x47f8f));
        objCallOnloadCallback((int*)ObjList_FindObjectById(0x47fa2));
        objCallOnloadCallback((int*)ObjList_FindObjectById(0x29f2));
        objCallOnloadCallback((int*)ObjList_FindObjectById(0x29f3));
        objCallOnloadCallback((int*)ObjList_FindObjectById(0x29ef));
        objCallOnloadCallback((int*)ObjList_FindObjectById(0x29ee));
        ((CfLevelControlFlags*)&state[0xc])->b3 = 0;
    }

    if ((*gMapEventInterface)->getMapAct(CFLEVELCONTROL_MAP_FORTRESS) == 1 &&
        mainGetBit(GAMEBIT_STAFF_ABILITY_SHARPCLAW_DISGUISE) != 0)
    {
        (*gMapEventInterface)->setMapAct(CFLEVELCONTROL_MAP_FORTRESS, 2);
    }

    /* sting on the first of the two fortress alarm bits, fanfare once
       both are set; the flag byte remembers last tick's values */
    bit974 = (u8)mainGetBit(GAMEBIT_CFLever0974);
    bit975 = mainGetBit(GAMEBIT_CFLever0975);
    if (((CfLevelControlFlags*)&state[0xc])->b5 == 0 || ((CfLevelControlFlags*)&state[0xc])->b4 == 0)
    {
        if (((CfLevelControlFlags*)&state[0xc])->b5 == 0 && ((CfLevelControlFlags*)&state[0xc])->b4 == 0)
        {
            if (bit974 != 0 || bit975 != 0)
            {
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            }
        }
        else if (bit974 != 0 && bit975 != 0)
        {
            Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
        }
    }

    ((CfLevelControlFlags*)&state[0xc])->b5 = bit974;
    ((CfLevelControlFlags*)&state[0xc])->b4 = bit975;

    if (obj->unkF4 == 0)
    {
        getEnvfxActImmediatelyVoid((void*)obj, (void*)obj, CFLEVELCONTROL_ENVFX_A, 0);
        if (mainGetBit(GAMEBIT_CFRelated0D73) == 0)
        {
            getEnvfxActImmediatelyVoid((void*)obj, (void*)obj, CFLEVELCONTROL_ENVFX_B, 0);
            getEnvfxActImmediatelyVoid((void*)obj, (void*)obj, CFLEVELCONTROL_ENVFX_C, 0);
            getEnvfxActImmediatelyVoid((void*)obj, (void*)obj, CFLEVELCONTROL_ENVFX_D, 0);
            skyFn_80088e54(0, lbl_803E43EC);
            mainSetBits(GAMEBIT_CFRelated0D73, 1);
        }

        if (mainGetBit(GAMEBIT_CFRelated0DCA) != 0)
        {
            getEnvfxActImmediatelyVoid((void*)obj, (void*)obj, CFLEVELCONTROL_ENVFX_B, 0);
            getEnvfxActImmediatelyVoid((void*)obj, (void*)obj, CFLEVELCONTROL_ENVFX_E, 0);
            getEnvfxActImmediatelyVoid((void*)obj, (void*)obj, CFLEVELCONTROL_ENVFX_F, 0);
            skyFn_80088e54(1, lbl_803E43EC);
            mainSetBits(GAMEBIT_CFRelated0DCA, 0);
            unlockLevel(0, 0, 1);
        }

        obj->unkF4 = 1;
    }

    if (mainGetBit(GAMEBIT_CF_NotRecoveredStaff) != 0 &&
        (((GameObject*)player)->objectFlags & CFLEVELCONTROL_OBJFLAG_PARENT_SLACK) == 0)
    {
        mainSetBits(GAMEBIT_CF_HaveStaff, 0);
    }

    bit94e = mainGetBit(GAMEBIT_CF_HaveStaff);
    if (bit94e != 0 && playerIsDisguised(player) == 0)
    {
        staffToggle((GameObject*)Obj_GetPlayerObject(), 0);
    }
    else if (bit94e == 0 && playerIsDisguised(player) == 0)
    {
        staffToggle((GameObject*)Obj_GetPlayerObject(), 1);
    }

    if (mainGetBit(GAMEBIT_CFRestartPointRelated0D3D) != 0)
    {
        (*gMapEventInterface)->restartPoint(&triggerPos, 0, getCurMapLayer(), 1);
        mainSetBits(GAMEBIT_CFRestartPointRelated0D3D, 0);
        getEnvfxActImmediatelyVoid((void*)obj, (void*)obj, CFLEVELCONTROL_ENVFX_B, 0);
        getEnvfxActImmediatelyVoid((void*)obj, (void*)obj, CFLEVELCONTROL_ENVFX_C, 0);
        skyFn_80088e54(1, lbl_803E43E8);
    }

    cameraMode = (*gCameraInterface)->getMode();
    switch (cameraMode)
    {
    case 0x47: /* the cell camera mode */
        if ((s8)state[0xd] != 0x47)
        {
            mainSetBits(GAMEBIT_SH_Entered00C0, 1);
        }
        break;
    default:
        if ((s8)state[0xd] == 0x47)
        {
            mainSetBits(GAMEBIT_SH_WarpStoneRelated01A8, 1);
        }
        break;
    }
    *(s8*)&state[0xd] = (s8)(*gCameraInterface)->getMode();

    SCGameBitLatch_Update(state + 8, 4, -1, -1, 0x983, 0xb0);
    SCGameBitLatch_Update(state + 8, 8, -1, -1, 0x983, 0x38);
    SCGameBitLatch_UpdateInverted(state + 8, 0x100, -1, -1, 0x983, 0x16);
    SCGameBitLatch_UpdateInverted(state + 8, 0x80, -1, -1, 0x983, 0x39);

    if (mainGetBit(GAMEBIT_CFRelated0983) == 0)
    {
        if (mainGetBit(GAMEBIT_CFRelated0E23) == 0)
        {
            SCGameBitLatch_UpdateInverted(state + 8, 0x200, -1, -1, 0x984, 0xad);
            SCGameBitLatch_Update(state + 8, 0x40, -1, -1, 0x984, 0x16);
        }
        if (mainGetBit(GAMEBIT_CFRelated0984) != 0)
        {
            SCGameBitLatch_Update(state + 8, 0x20, -1, -1, 0xe23, 0x17);
            SCGameBitLatch_UpdateInverted(state + 8, 0x400, -1, -1, 0xe23, 0x16);
        }
    }

    SCGameBitLatch_Update(state + 8, 1, 0x1a8, 0xc0, 0xdb8, 0xae);
    SCGameBitLatch_Update(state + 8, 0x10, -1, -1, 0xe1d, 0x36);
    SCGameBitLatch_Update(state + 8, 0x1000, -1, -1, 0xe1d, 0xf1);
    SCGameBitLatch_Update(state + 8, 2, -1, -1, 0xb46, 0xaf);
    SCGameBitLatch_Update(state + 8, 0x800, -1, -1, 0xcbb, 0xc4);
}

void cflevelcontrol_init(u8* obj, u8* params)
{
    u8* sub;
    int i;

    sub = ((GameObject*)obj)->extra;
    ((CflevelcontrolState*)sub)->unk8 = 0;
    ((CflevelcontrolState*)sub)->unkD = -1;
    storeZeroToFloatParam(sub);
    s16toFloat(sub, 0x1e0);
    ((CfLevelControlFlags*)(sub + 0xc))->b6 = 0;
    ((GameObject*)obj)->animEventCallback = CFLevelControl_SeqFn;
    mainSetBits(GAMEBIT_CFRelated0983, *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14) != 0x2cef);
    if (mainGetBit(GAMEBIT_CFRelated02FE) == 0)
    {
        for (i = 0; i < 0x17; i++)
        {
            mainSetBits(lbl_80323008[i], 0);
        }
    }
    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 4, 0);
    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0x11, 0);
    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0x15, 0);
    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0x16, 0);
    ((CfLevelControlFlags*)(sub + 0xc))->b5 = mainGetBit(GAMEBIT_CFLever0974);
    ((CfLevelControlFlags*)(sub + 0xc))->b4 = mainGetBit(GAMEBIT_CFLever0975);
    objSetSlot(obj, 0x51);
    ((CfLevelControlFlags*)(sub + 0xc))->b3 = 1;
}

void cflevelcontrol_release(void)
{
}

void cflevelcontrol_initialise(void)
{
}
