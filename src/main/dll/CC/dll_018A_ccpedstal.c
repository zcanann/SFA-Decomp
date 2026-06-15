/* DLL 0x018A - ccpedstal (Crystal Caves pedestal gate). TU: 0x801AB6F8-0x801ABA84. */
#include "main/dll/DIM/dimlogfire.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);

/* 8b "li r3, N; blr" returners. */

#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/objfx.h"
#include "main/objseq.h"
#include "main/dll/DIM/DIMsnowball.h"
#include "main/dll/SC/SCtotemlogpuz.h"

extern int ObjTrigger_IsSetById();
extern int ObjTrigger_IsSet();
extern undefined4 FUN_8008112c();

extern f32 lbl_803E530C;
extern f32 lbl_803E5310;
extern f32 lbl_803E5314;
extern f32 lbl_803E5360;

/* ccpedstal extra block (extraSize 0x8): a think fn-pointer at +0, an
 * s16 GameBit id at +4, and a one-shot flag byte at +6 toggled by the
 * think routines and consumed by ccpedstal_update. */
typedef struct CcpedstalState
{
    void* think;
    s16 gameBit;
    u8 markFlags;
    u8 unk7;
} CcpedstalState;

STATIC_ASSERT(offsetof(CcpedstalState, gameBit) == 0x4);
STATIC_ASSERT(offsetof(CcpedstalState, markFlags) == 0x6);
STATIC_ASSERT(sizeof(CcpedstalState) == 0x8);

#pragma scheduling on
#pragma peephole on
extern void ccpedstal_updateGameBitGate(int obj, u8* state2);
extern void ccpedstal_updateAltVariant(int obj, u8* state2);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern void gameBitDecrement(int id);
extern int ObjTrigger_IsSet(int obj);
extern void gameBitIncrement(int id);
extern void* fn_802972A8(void* obj);

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
int ccpedstal_getExtraSize(void) { return 0x8; }
int cclevcontrol_getExtraSize(void);

#pragma scheduling off
#pragma peephole off
void ccpedstal_init(int* obj, u8* params)
{
    CcpedstalState* state = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)((u32)params[0x1a] << 8);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x4000);
    switch (*(int*)(params + 0x14))
    {
    case 0x45f1a:
        state->think = (void*)ccpedstal_updateAltVariant;
        state->gameBit = 0xaa;
        Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 3);
        break;
    case 0x45f1b:
        state->think = (void*)ccpedstal_updateGameBitGate;
        state->gameBit = 0xf1;
        break;
    case 0x45f1c:
        state->think = (void*)ccpedstal_updateGameBitGate;
        state->gameBit = 0xfe;
        break;
    }
}

void cclevcontrol_init(int* obj);

#pragma dont_inline on
#pragma dont_inline reset

/* ccpedstal_updateGameBitGate: state2-driven model + trigger gate. If state2's gamebit at
 * +0x4 is set, latches obj[0xaf] bit 8 and selects model index 1.
 * Otherwise selects model 0, then consults gbit 0xa9: if set, clears the
 * 0x10 flag and (if the obj's trigger 0xa9 is set) fires vtable[0x12],
 * decrements the gamebit, and flags state2[0x6] bit 0. If gbit 0xa9 is
 * clear, sets the obj[0xaf] 0x10 flag instead. */
void ccpedstal_updateGameBitGate(int obj, u8* state2)
{
    CcpedstalState* state = (CcpedstalState*)state2;
    if (GameBit_Get(state->gameBit) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
        Obj_SetActiveModelIndex(obj, 1);
    }
    else
    {
        int doMark;
        Obj_SetActiveModelIndex(obj, 0);
        if (GameBit_Get(0xa9) != 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x10);
            if (ObjTrigger_IsSetById(obj, 0xa9) != 0)
            {
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                gameBitDecrement(0xa9);
                doMark = 1;
                goto check;
            }
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x10);
        }
        doMark = 0;
    check:
        if (doMark != 0)
        {
            state->markFlags = (u8)(state->markFlags | 1);
        }
    }
}

/* ccpedstal_updateAltVariant: ccpedstal alt-variant think-routine. Toggles obj[0xaf]
 * bit 8 from gbit 0xdc5, then reads state2's gamebit at +0x4: if set,
 * sets bit 8 again and selects model 0; if clear, selects model 1 and
 * (when the obj's pending trigger is asserted) fires vtable[0x12] with
 * id=1, increments gbit 0xa9, and latches state2[0x6] bit 0. Mirrors
 * the no-mark branches into a shared r0=0/cmpwi end-check via goto to
 * match target's layout. */
void ccpedstal_updateAltVariant(int obj, u8* state2)
{
    CcpedstalState* state = (CcpedstalState*)state2;
    if (GameBit_Get(0xdc5) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~8);
    }
    if (GameBit_Get(state->gameBit) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
        Obj_SetActiveModelIndex(obj, 0);
    }
    else
    {
        int doMark;
        Obj_SetActiveModelIndex(obj, 1);
        if (ObjTrigger_IsSet(obj) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
            gameBitIncrement(0xa9);
            doMark = 1;
            goto check;
        }
        doMark = 0;
    check:
        if (doMark != 0)
        {
            state->markFlags = (u8)(state->markFlags | 1);
        }
    }
}

void ccpedstal_update(int obj)
{
    CcpedstalState* state = ((GameObject*)obj)->extra;
    if (state->markFlags != 0)
    {
        if (state->markFlags & 1)
        {
            GameBit_Set(state->gameBit, 1);
        }
        else
        {
            GameBit_Set(state->gameBit, 0);
        }
        state->markFlags = 0;
        if (GameBit_Get(0xdf0) == 0 && GameBit_Get(0xaa) != 0)
        {
            GameBit_Set(0xdf0, 1);
        }
    }
    (*(void (*)(int, int))state->think)(obj, (int)state);
}
