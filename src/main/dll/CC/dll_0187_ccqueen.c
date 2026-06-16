/* DLL 0x0187 (ccqueen) — CloudRunner Queen object [0x801AA558-0x801AA734). */
#include "main/dll/DIM/dimlogfire.h"

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);

int ccqueen_getExtraSize(void) { return 0x654; }

extern void objRenderFn_8003b8f4(f32);

extern f32 timeDelta;

#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objseq.h"

extern undefined4 ObjHits_DisableObject();
extern undefined4 FUN_8008112c();
extern undefined4 dll_2E_func03();
extern void dll_2E_func06(int* obj, void* state, int flags);

extern f32 lbl_803E4660;
extern f32 lbl_803E530C;
extern f32 lbl_803E5310;
extern f32 lbl_803E5314;
extern f32 lbl_803E5360;

void ccqueen_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    extern undefined4 ccqueen_render();
    void* state = ((GameObject*)obj)->extra;
    objRenderFn_8003b8f4(lbl_803E4660);
    dll_2E_func06(obj, state, 0);
}

#pragma scheduling on
#pragma peephole on
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

extern void dll_2E_func05(int* obj, u8* sub, int a, int b, int c);
extern void dll_2E_func08(u8* sub, int a, int b);
extern void dll_2E_func09(u8* sub, void* a, void* b, int c);

typedef struct
{
    s16 v[3];
} _S16x3;

extern _S16x3 lbl_803E4650;
extern _S16x3 lbl_803E4658;

#pragma scheduling off
#pragma peephole off
void ccqueen_init(int* obj, u8* init)
{
    u8* sub;
    _S16x3 buf2;
    _S16x3 buf1;
    sub = ((GameObject*)obj)->extra;
    buf2 = lbl_803E4650;
    buf1 = lbl_803E4658;
    ((GameObject*)obj)->anim.rotX = (s16)(init[0x1a] << 8);
    dll_2E_func05(obj, sub, 0x71c7, 0x3555, 3);
    dll_2E_func08(sub, 0x258, 0xf0);
    dll_2E_func09(sub, &buf1, &buf2, 3);
    sub[0x611] = (u8)(sub[0x611] | 0xa);
}

extern f32 lbl_803E4664;
extern f32 lbl_803E4668;
extern f32 vec3f_distanceSquared(f32 * p1, f32 * p2);
extern void characterDoEyeAnims(int obj, void* p);

void ccqueen_update(int* obj)
{
    extern void* Obj_GetPlayerObject(void);
    u8* sub;
    int* player;

    sub = ((GameObject*)obj)->extra;
    if (GameBit_Get(0x1c2) == 0 && GameBit_Get(0xa3) != 0)
    {
        player = (int*)Obj_GetPlayerObject();
        if (vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <
            lbl_803E4664)
        {
            GameBit_Set(0x1c2, 1);
        }
    }
    if (GameBit_Get(0x1c3) != 0)
    {
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x8000);
        ObjHits_DisableObject(obj);
    }
    else
    {
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E4668, timeDelta, NULL);
        dll_2E_func03(obj, sub);
        characterDoEyeAnims((int)obj, sub + 0x624);
    }
}

int ccqueen_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

