/*
 * cclevcontrol - Crystal Caves level-control object (DLL 0x018B). The
 * per-level director object: it drives the day/night music transition off
 * the sky sun position, fans a set of SCGameBitLatch updates that gate
 * puzzle/door object groups on gameBits, toggles a triggered camera action
 * from the SharpClaw-encounter gameBits, runs the intro env-fx in init and
 * an end-of-level sfx once all the collectables are in.
 *
 * The extra block (0x10 bytes): a help-text hold timer at +0, a latch/flags
 * word at +4 (an SCGameBitLatchState), the current music state at +8 and the
 * cached map-act at +0xC.
 */
#include "main/sky_interface.h"
#include "main/audio/music_api.h"
#include "main/object_render_legacy.h"
#include "main/object.h"
#include "main/render_envfx_api.h"
#include "main/camera_interface.h"
#include "main/game_object.h"
#include "main/objfx.h"
#include "main/objanim_update.h"
#include "main/dll/SH/dll_01AE_shlevelcontrol.h"
#include "main/mapEventTypes.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/dll/savegame_load_api.h"
#include "main/gametext_show_api.h"
#include "main/sky_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/CC/dll_018B_cclevcontrol.h"
#include "main/object_descriptor.h"

#define CCLEVCONTROL_OBJFLAG_PARENT_SLACK 0x1000
#define CCLEVCONTROL_ENVFX_A              0x242

int lbl_80323548[56] = {
    0x02410241, 0x02410241, 0x02410241, 0x02410241, 0x02410241, 0x02410241, 0x02410241, 0x02410241,
    0x02410241, 0x02410241, 0x02410241, 0x02410241, 0x02410241, 0x02410241, 0x023F023F, 0x023F023F,
    0x023F023F, 0x023F023F, 0x023F023F, 0x023F023F, 0x023F023F, 0x023F023F, 0x023F023F, 0x023F023F,
    0x023F023F, 0x023F023F, 0x023F023F, 0x023F023F, 0x02400240, 0x02400243, 0x02400243, 0x02430240,
    0x02400240, 0x02400240, 0x02400240, 0x02400240, 0x02430243, 0x02430240, 0x02400240, 0x02400240,
    0x02400240, 0x02400240, -1,         -1,         -1,         -1,         -1,         -1,
    -1,         -1,         -1,         -1,         -1,         -1,         -1,         -1,
};


extern void fn_80088870(void* a, void* b, void* c, void* d);



int cclevcontrol_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    if (animUpdate->eventCount != 0)
    {
        spawnExplosionLegacy(obj, 50.0f, 1, 1, 0, 1, 1, 1, 0);
    }
    return 0;
}

int cclevcontrol_getExtraSize(void)
{
    return 0x10;
}

void cclevcontrol_free(void)
{
    envFxActFn_800887f8(0);
    Music_Trigger(MUSICTRIG_Arwing_Crash, 0);
}

void cclevcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
}

void cclevcontrol_update(GameObject* obj)
{
    int* state = (obj)->extra;
    int* tricky;
    u32 collectBitA;
    u32 collectBitB;

    if (*(f32*)state > 0.0f)
    {
        gameTextShow(0x34c);
        *(f32*)state -= timeDelta;
        if (*(f32*)state < 0.0f)
        {
            *(f32*)state = 0.0f;
        }
    }
    if ((*gSkyInterface)->getSunPosition(0) != 0)
    {
        if (state[2] != -1)
        {
            state[2] = -1;
            if (state[1] & 0x20)
            {
                Music_Trigger(MUSICTRIG_Arwing_Crash, 0);
            }
        }
    }
    else
    {
        if (state[2] != 0xc8)
        {
            state[2] = 0xc8;
            if (state[1] & 0x20)
            {
                Music_Trigger(MUSICTRIG_Arwing_Crash, 1);
            }
        }
    }
    SCGameBitLatch_Update((SCGameBitLatchState*)(state + 1), 2, -1, -1, 0xb72, 0x95);
    SCGameBitLatch_Update((SCGameBitLatchState*)(state + 1), 0x20, -1, -1, 0xc47, state[2]);
    SCGameBitLatch_Update((SCGameBitLatchState*)(state + 1), 4, -1, -1, 0xb45, 0x37);
    SCGameBitLatch_Update((SCGameBitLatchState*)(state + 1), 8, -1, -1, 0xb73, 0xbf);
    SCGameBitLatch_Update((SCGameBitLatchState*)(state + 1), 0x10, -1, -1, 0xb24, 0xc0);
    SCGameBitLatch_Update((SCGameBitLatchState*)(state + 1), 0x40, -1, -1, 0x19e, 0xcd);
    if (state[3] == 2)
    {
        SCGameBitLatch_UpdateInverted((SCGameBitLatchState*)(state + 1), 0x80, -1, -1, 0x24, 0xea);
    }
    if (mainGetBit(0x3d6) != 0 && (u8)(*gMapEventInterface)->getObjGroupStatus((obj)->anim.mapEventSlot, 0x1f) != 0)
    {
        (*gMapEventInterface)->setObjGroupStatus((obj)->anim.mapEventSlot, 0x1f, 0);
    }
    if (mainGetBit(0x161) != 0 && (u8)(*gMapEventInterface)->getObjGroupStatus((obj)->anim.mapEventSlot, 0x1e) == 0)
    {
        (*gMapEventInterface)->setObjGroupStatus((obj)->anim.mapEventSlot, 0x1e, 1);
    }
    if (mainGetBit(0x3d7) != 0 && (u8)(*gMapEventInterface)->getObjGroupStatus((obj)->anim.mapEventSlot, 0x1d) == 0)
    {
        (*gMapEventInterface)->setObjGroupStatus((obj)->anim.mapEventSlot, 0x1d, 1);
    }
    tricky = (int*)getTrickyObject();
    if (state[1] & 1)
    {
        if (mainGetBit(0x22d) != 0 || mainGetBit(0x22e) == 0 ||
            (((GameObject*)tricky)->objectFlags & CCLEVCONTROL_OBJFLAG_PARENT_SLACK) != 0)
        {
            state[1] &= ~1;
            (*gCameraInterface)->loadTriggeredCamAction(0, 1, 0);
        }
    }
    else
    {
        if (mainGetBit(0x22d) == 0 && mainGetBit(0x22a) != 0 && mainGetBit(0x22e) != 0 && mainGetBit(0x160) == 0)
        {
            state[1] |= 1;
            (*gCameraInterface)->loadTriggeredCamAction(1, 1, 0);
        }
    }
    collectBitA = mainGetBit(GAMEBIT_ITEM_CCGoldBar_Used);
    collectBitB = mainGetBit(GAMEBIT_ITEM_CCGoldBar_Count);
    if (collectBitB + collectBitA == 4 && mainGetBit(0xf26) == 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_mpick1_b);
        mainSetBits(0xf26, 1);
    }
}

void cclevcontrol_init(int* obj)
{
    void* envfxTable;
    int* state;
    envfxTable = lbl_80323548;
    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = cclevcontrol_SeqFn;
    fn_80088870((char*)envfxTable + 0x38, envfxTable, (char*)envfxTable + 0x70, (char*)envfxTable + 0xa8);
    if (getSaveGameLoadStatus() != 0)
    {
        envFxActFn_800887f8(0x3f);
        getEnvfxActImmediatelyVoid((void*)0, 0, CCLEVCONTROL_ENVFX_A, 0);
    }
    else
    {
        envFxActFn_800887f8(0x1f);
        getEnvfxActInt(0, 0, CCLEVCONTROL_ENVFX_A, 0);
    }
    *(f32*)state = 300.0f;
    state[2] = -1;
    state[3] = (u32)(u8)(*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot);
}

ObjectDescriptor gCClevcontrolObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)cclevcontrol_init,
    (ObjectDescriptorCallback)cclevcontrol_update,
    0,
    (ObjectDescriptorCallback)cclevcontrol_render,
    (ObjectDescriptorCallback)cclevcontrol_free,
    0,
    cclevcontrol_getExtraSize,
};
