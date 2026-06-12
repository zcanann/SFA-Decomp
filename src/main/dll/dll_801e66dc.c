/* DLL 0x801E66DC — SB ship gun and related Starfox battle objects [0x801E66DC-0x801E67BC). */
#include "main/dll_000A_expgfx.h"
#include "main/dll/shipbattlestate_struct.h"
#include "main/dll/sbkytecagestate_struct.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/sbcloudballstate_struct.h"
#include "main/dll/TREX/TREX_levelcontrol.h"









/*
 * --INFO--
 *
 * Function: SB_ShipGun_update
 * EN v1.0 Address: 0x801E34C0
 * EN v1.0 Size: 2312b
 * EN v1.1 Address: 0x801E3AB0
 * EN v1.1 Size: 2132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */



/* Trivial 4b 0-arg blr leaves. */



/* 8b "li r3, N; blr" returners. */




/* render-with-objRenderFn_8003b8f4 pattern. */









#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/mapEvent.h"
#include "main/dll/TREX/TREX_trex.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/objhits_types.h"
#include "main/objseq.h"
#include "main/resource.h"











/*
 * Per-object extra state for the ShipBattle cloud-ball projectile
 * (SB_CloudBall_getExtraSize == 0x24).
 */


STATIC_ASSERT(sizeof(SBCloudBallState) == 0x24);

/*
 * Per-object extra state for the ShipBattle fireball projectile
 * (SB_FireBall_getExtraSize == SB_FIREBALL_EXTRA_SIZE == 0x18).
 */


STATIC_ASSERT(sizeof(SBFireBallState) == 0x18);

/*
 * Per-object extra state for the ShipBattle kyte cage
 * (SB_KyteCage_getExtraSize == 0x8).
 */


STATIC_ASSERT(sizeof(SBKyteCageState) == 0x8);

/*
 * Per-object extra state for the ShipBattle chain segment
 * (ShipBattle_getExtraSize == 0x140). The head is handed to
 * gObjectTriggerInterface (+0x1C/+0x24) - interface-owned record;
 * only the locally-evidenced fields are named.
 */


STATIC_ASSERT(sizeof(ShipBattleState) == 0x140);




/*
 * --INFO--
 *
 * Function: SB_FireBall_hitDetect
 * EN v1.0 Address: 0x801E42F8
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801E4330
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801e4350
 * EN v1.0 Address: 0x801E4350
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E4384
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801e48f4
 * EN v1.0 Address: 0x801E48F4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801E4888
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801e4928
 * EN v1.0 Address: 0x801E4928
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E48B8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801e521c
 * EN v1.0 Address: 0x801E521C
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x801E5194
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801e524c
 * EN v1.0 Address: 0x801E524C
 * EN v1.0 Size: 884b
 * EN v1.1 Address: 0x801E51CC
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801e55c0
 * EN v1.0 Address: 0x801E55C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E5450
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void FUN_801e55c0(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined2* param_9, int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801e55c4
 * EN v1.0 Address: 0x801E55C4
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x801E5564
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void SB_FireBall_release(void);


































/* 8b "li r3, N; blr" returners. */
int fn_801E66DC(void) { return 0x0; }
int fn_801E66E4(void) { return 0x0; }

/* 16b chained patterns. */
s32 shop_getStateField1(int* obj);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E59D8;
extern f32 lbl_803E59DC;
extern int* gBoneParticleEffectInterface;
extern int Stack_IsEmpty(int stack);
extern int Stack_Pop(int stack, int* out);






/* Stubs added to align function set with v1.0 asm. Source had Ghidra FUN_xxx
 * splits at wrong addresses; these stubs ensure every asm symbol has a src
 * definition so future hunters can fill bodies one at a time. */



/* EN v1.0 0x801E4F14  size: 60b  Decrement obj->_f4 if > 0, OR in bit 0x8
 * of obj->_af, latch state->_6e = -2 and state->_56 = 0; return 0. */




int fn_801E66EC(int arg1, int arg2)
{
    int state;
    f32 local;
    int stk;
    int popOut;

    state = *(int*)(arg1 + 0xb8);
    local = lbl_803E59D8;

    if (*(s8*)(arg2 + 0x27a) != 0)
    {
        if ((*(u16*)(arg1 + 0xb0) & 0x800) != 0)
        {
            ((void (*)(int, int, f32*, int, int))((void**)*gBoneParticleEffectInterface)[3])(
                arg1, 2031, &local, 80, 0);
        }
    }

    *(u8*)(state + 0x9d6) = 0;
    *(f32*)(arg2 + 0x280) = lbl_803E59DC;
    if (*(u8*)(state + 0x9d6) == 0)
    {
        stk = *(int*)(state + 0x9b0);
        popOut = 0;
        if (Stack_IsEmpty(stk) == 0)
        {
            Stack_Pop(stk, &popOut);
        }
        return popOut + 1;
    }
    return 0;
}

void Lamp_free(int* obj);















/* EN v1.0 0x801E4BA4  size: 48b  When obj->_b8->[0] is non-null,
 * call ObjLink_DetachChild(obj). */























/* EN v1.0 0x801E60A4  size: 28b  shop state reset/seed: zero obj->_b8[2]
 * and obj->_b8[3], stash (s8)v in obj->_b8[4]. */

/* EN v1.0 0x801E607C  size: 40b  Increment-and-store: obj->_b8[2] += p3,
 * obj->_b8[3] += p2. */

/* EN v1.0 0x801E6050  size: 44b  Triple s8 fan-out: write obj->_b8[2/3/4]
 * (sign-extended) into *out_b3, *out_b2, *out_b4. */

/* shop_getItem* helpers -- table lookup */





/* EN v1.0 0x801E6358  size: 104b  Returns 1 unless the item's
 * "available" GameBit gate (lbl_80327FD0[idx*12 + 6]) is present and
 * unset.  (i.e. open by default, gated when slot != -1.) */

/* EN v1.0 0x801E62F0  size: 104b  Returns 1 when shop item's "bought"
 * GameBit (slot at lbl_80327FD0[idx*12 + 8]) is set; else 0. */


