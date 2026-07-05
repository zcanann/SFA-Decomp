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
#include "main/camera_interface.h"
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/dll/SC/SCtotemlogpuz.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/sfa_shared_decls.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#define CCLEVCONTROL_OBJFLAG_PARENT_SLACK 0x1000
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern f32 timeDelta;


extern void Music_Trigger(int id, int arg);
extern void spawnExplosion(int obj, f32 scale, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
extern void fn_80088870(void* a, void* b, void* c, void* d);

extern void getEnvfxActImmediately(void* obj, void* target, int animId, int flags);
extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern int lbl_80323548[];

extern f32 lbl_803E46C8; /* SeqFn explosion scale */
extern f32 lbl_803E46CC; /* render scale */
extern f32 lbl_803E46D0; /* help-text hold floor */
extern f32 lbl_803E46D4; /* help-text hold reset value */

int cclevcontrol_getExtraSize(void) { return 0x10; }

void cclevcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E46CC); }

void cclevcontrol_free(void)
{
    envFxActFn_800887f8(0);
    Music_Trigger(MUSICTRIG_Arwing_Crash, 0);
}

int cclevcontrol_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    if (animUpdate->eventCount != 0)
    {
        spawnExplosion(obj, lbl_803E46C8, 1, 1, 0, 1, 1, 1, 0);
    }
    return 0;
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
        getEnvfxActImmediately((void*)0, 0, 0x242, 0);
    }
    else
    {
        envFxActFn_800887f8(0x1f);
        getEnvfxAct(0, 0, 0x242, 0);
    }
    *(f32*)state = lbl_803E46D4;
    state[2] = -1;
    state[3] = (u32)(u8)(*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot);
}

void cclevcontrol_update(int obj)
{
    extern void* getTrickyObject(void);
    int* state = ((GameObject*)obj)->extra;
    int* tricky;
    u32 collectBitA;
    u32 collectBitB;

    if (*(f32*)state > lbl_803E46D0)
    {
        gameTextShow(0x34c);
        *(f32*)state -= timeDelta;
        if (*(f32*)state < lbl_803E46D0)
        {
            *(f32*)state = *(f32*)&lbl_803E46D0;
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
    if (GameBit_Get(0x3d6) != 0
        && (u8)(*gMapEventInterface)->getObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0x1f) != 0)
    {
        (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0x1f, 0);
    }
    if (GameBit_Get(0x161) != 0
        && (u8)(*gMapEventInterface)->getObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0x1e) == 0)
    {
        (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0x1e, 1);
    }
    if (GameBit_Get(0x3d7) != 0
        && (u8)(*gMapEventInterface)->getObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0x1d) == 0)
    {
        (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0x1d, 1);
    }
    tricky = getTrickyObject();
    if (state[1] & 1)
    {
        if (GameBit_Get(0x22d) != 0 || GameBit_Get(0x22e) == 0
            || (((GameObject*)tricky)->objectFlags & CCLEVCONTROL_OBJFLAG_PARENT_SLACK) != 0)
        {
            state[1] &= ~1;
            (*gCameraInterface)->loadTriggeredCamAction(0, 1, 0);
        }
    }
    else
    {
        if (GameBit_Get(0x22d) == 0 && GameBit_Get(0x22a) != 0 && GameBit_Get(0x22e) != 0
            && GameBit_Get(0x160) == 0)
        {
            state[1] |= 1;
            (*gCameraInterface)->loadTriggeredCamAction(1, 1, 0);
        }
    }
    collectBitA = GameBit_Get(0x3f0);
    collectBitB = GameBit_Get(0xaf7);
    if (collectBitB + collectBitA == 4 && GameBit_Get(0xf26) == 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_mpick1_b);
        GameBit_Set(0xf26, 1);
    }
}
