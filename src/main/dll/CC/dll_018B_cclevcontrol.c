/* DLL 0x018B — CC level-control objects [801AA558-801AA560) */
#include "main/dll/DIM/dimlogfire.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/sky_interface.h"

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);

extern void objRenderFn_8003b8f4(f32);

extern f32 timeDelta;
extern void Sfx_PlayFromObject(int obj, int id);

#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/objfx.h"
#include "main/objseq.h"
#include "main/dll/DIM/DIMsnowball.h"
#include "main/dll/SC/SCtotemlogpuz.h"

extern undefined4 FUN_8008112c();

extern f32 lbl_803E530C;
extern f32 lbl_803E5310;
extern f32 lbl_803E5314;
extern f32 lbl_803E5360;

#pragma scheduling on
#pragma peephole on
extern f32 lbl_803E46CC;
extern void envFxActFn_800887f8(int a);
extern void Music_Trigger(int a, int b);
extern void spawnExplosion(int obj, f32 scale, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
extern f32 lbl_803E46C8;
extern void fn_80088870(void* a, void* b, void* c, void* d);
extern int getSaveGameLoadStatus(void);
extern void getEnvfxActImmediately(void* obj, void* target, int animId, int flags);
extern void getEnvfxAct(int obj, int target, int id, int p);
extern int lbl_80323548[];
extern f32 lbl_803E46D4;
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern f32 lbl_803E46D0;
extern void gameTextShow(int textId);

void FUN_801aaa6c(double value, int state, int obj)
{
    if ((double)lbl_803E530C == value)
    {
        *(u8*)(state + 0x10) = 0xc;
        return;
    }
    if ((*(byte*)(state + 0x11) & 2) != 0)
    {
        *(u8*)(state + 0x10) = 1;
        return;
    }
    if ((double)lbl_803E5310 <= value)
    {
        *(u8*)(state + 0x10) = 2;
        return;
    }
    if ((*(short*)(obj + 0xa0) == 0x18) && (lbl_803E5314 < *(float*)(obj + 0x98)))
    {
        *(u8*)(state + 0x10) = 8;
        return;
    }
    if (*(short*)(obj + 0xa0) == 0x19)
    {
        *(u8*)(state + 0x10) = 5;
        return;
    }
    *(u8*)(state + 0x10) = 0xb;
    return;
}

undefined4
FUN_801abf38(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, undefined4 obj,
             undefined4 param_10, ObjAnimUpdateState* animUpdate)
{
    if (animUpdate->eventCount != 0)
    {
        FUN_8008112c((double)lbl_803E5360, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 1, 1, 0, 1, 1, 1, 0);
    }
    return 0;
}

int cclightfoot_getExtraSize(void);
int cclevcontrol_getExtraSize(void) { return 0x10; }

void cclevcontrol_render(void) { objRenderFn_8003b8f4(lbl_803E46CC); }

#pragma scheduling off
#pragma peephole off
void cclevcontrol_free(void)
{
    envFxActFn_800887f8(0);
    Music_Trigger(200, 0);
}

void cclightfoot_init(int* obj, int* def);

int cclevcontrol_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    if (animUpdate->eventCount != 0)
    {
        spawnExplosion(obj, lbl_803E46C8, 1, 1, 0, 1, 1, 1, 0);
    }
    return 0;
}

void cclightfoot_free(int* obj, int p2);

void cclevcontrol_init(int* obj)
{
    void* envfxTable;
    int* state;
    envfxTable = lbl_80323548;
    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)cclevcontrol_SeqFn;
    fn_80088870((char*)envfxTable + 0x38, envfxTable, (char*)envfxTable + 0x70, (char*)envfxTable + 0xa8);
    if (getSaveGameLoadStatus() != 0)
    {
        envFxActFn_800887f8(0x3f);
        getEnvfxActImmediately((void*)0, (void*)0, 0x242, 0);
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

#pragma dont_inline on
#pragma dont_inline reset

/* ccpedstal_updateGameBitGate: state2-driven model + trigger gate. If state2's gamebit at
 * +0x4 is set, latches obj[0xaf] bit 8 and selects model index 1.
 * Otherwise selects model 0, then consults gbit 0xa9: if set, clears the
 * 0x10 flag and (if the obj's trigger 0xa9 is set) fires vtable[0x12],
 * decrements the gamebit, and flags state2[0x6] bit 0. If gbit 0xa9 is
 * clear, sets the obj[0xaf] 0x10 flag instead. */

/* ccpedstal_updateAltVariant: ccpedstal alt-variant think-routine. Toggles obj[0xaf]
 * bit 8 from gbit 0xdc5, then reads state2's gamebit at +0x4: if set,
 * sets bit 8 again and selects model 0; if clear, selects model 1 and
 * (when the obj's pending trigger is asserted) fires vtable[0x12] with
 * id=1, increments gbit 0xa9, and latches state2[0x6] bit 0. Mirrors
 * the no-mark branches into a shared r0=0/cmpwi end-check via goto to
 * match target's layout. */

void cclevcontrol_update(int obj)
{
    extern void* getTrickyObject(void);
    int* state = ((GameObject*)obj)->extra;
    int* tricky;
    u32 a;
    u32 b;

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
                Music_Trigger(0xc8, 0);
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
                Music_Trigger(0xc8, 1);
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
    tricky = (int*)getTrickyObject();
    if (state[1] & 1)
    {
        if (GameBit_Get(0x22d) != 0 || GameBit_Get(0x22e) == 0
            || (((GameObject*)tricky)->objectFlags & 0x1000) != 0)
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
    a = GameBit_Get(0x3f0);
    b = GameBit_Get(0xaf7);
    if (b + a == 4 && GameBit_Get(0xf26) == 0)
    {
        Sfx_PlayFromObject(obj, 0x7e);
        GameBit_Set(0xf26, 1);
    }
}
