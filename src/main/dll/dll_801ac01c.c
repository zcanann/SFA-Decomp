/* DLL — DIM log-fire objects [801AA558-801AA560) */
#include "main/dll/DIM/dimlogfire.h"
#include "main/mapEventTypes.h"

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);

/* 8b "li r3, N; blr" returners. */

#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/objseq.h"

extern undefined4 FUN_8008112c();

extern f32 lbl_803E530C;
extern f32 lbl_803E5310;
extern f32 lbl_803E5314;
extern f32 lbl_803E5360;

extern void* fn_802972A8(void* obj);
extern int mapGetDirIdx(int a);
extern void lockLevel(int idx, int flag);
extern f32 lbl_803E46A8;

void FUN_801aaa6c(double param_1, int param_2, int param_3)
{
    if ((double)lbl_803E530C == param_1)
    {
        *(u8*)(param_2 + 0x10) = 0xc;
        return;
    }
    if ((*(byte*)(param_2 + 0x11) & 2) != 0)
    {
        *(u8*)(param_2 + 0x10) = 1;
        return;
    }
    if ((double)lbl_803E5310 <= param_1)
    {
        *(u8*)(param_2 + 0x10) = 2;
        return;
    }
    if ((*(short*)(param_3 + 0xa0) == 0x18) && (lbl_803E5314 < *(float*)(param_3 + 0x98)))
    {
        *(u8*)(param_2 + 0x10) = 8;
        return;
    }
    if (*(short*)(param_3 + 0xa0) == 0x19)
    {
        *(u8*)(param_2 + 0x10) = 5;
        return;
    }
    *(u8*)(param_2 + 0x10) = 0xb;
    return;
}

undefined4
FUN_801abf38(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, undefined4 param_9,
             undefined4 param_10, ObjAnimUpdateState* animUpdate)
{
    if (animUpdate->eventCount != 0)
    {
        FUN_8008112c((double)lbl_803E5360, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 1, 1, 0, 1, 1, 1, 0);
    }
    return 0;
}

int cclightfoot_getExtraSize(void);

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

#pragma scheduling off
void fn_801AC01C(int obj)
{
    extern void* Obj_GetPlayerObject(void);
    int state = *(int*)&((GameObject*)obj)->extra;
    int r;
    void* res;
    GameBit_Set(0x3a3, 0);
    GameBit_Set(0x3a2, 0);
    res = fn_802972A8(Obj_GetPlayerObject());
    if (res != 0)
    {
        r = (*(int (**)(int))(*(int*)(*(int*)&((GameObject*)res)->anim.dll) + 0x48))((int)res);
    }
    else
    {
        r = 0;
    }
    lockLevel(mapGetDirIdx(0x17), 1);
    if (r == 1)
    {
        (*gGameUIInterface)->setShowWorldMapHud(1);
        *(u8*)(state + 0) = 5;
        GameBit_Set(0x37b, 1);
    }
    else
    {
        *(u8*)(state + 0) = 6;
        GameBit_Set(0xce, 1);
    }
    GameBit_Set(0x378, 0);
    GameBit_Set(0x3b9, 0);
}

void fn_801AC108(int obj, int param2)
{
    extern void* Obj_GetPlayerObject(void);
    int r;
    void* res;
    (*gGameUIInterface)->setShowWorldMapHud(0);
    if (GameBit_Get(0x3a3) != 0)
    {
        GameBit_Set(0x3a3, 0);
        GameBit_Set(0x3a2, 0);
        GameBit_Set(0x378, 0);
        GameBit_Set(0x3b9, 0);
        res = fn_802972A8(Obj_GetPlayerObject());
        if (res != 0)
        {
            r = (*(int (**)(int))(*(int*)(*(int*)&((GameObject*)res)->anim.dll) + 0x48))((int)res);
        }
        else
        {
            r = 0;
        }
        GameBit_Set(0x4e5, 1);
        (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 1, 1);
        if (r == 1)
        {
            (*gGameUIInterface)->setShowWorldMapHud(1);
            *(u8*)(param2 + 0) = 5;
            GameBit_Set(0x379, 1);
        }
        else
        {
            *(u8*)(param2 + 0) = 6;
            GameBit_Set(0xcb, 1);
        }
    }
}
