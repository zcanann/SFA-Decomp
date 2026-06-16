/* DLL 0x01F6 — Flag (decorative flag object). TU: 0x801E5DC4–0x801E5F74. */
#include "main/dll/shipbattlestate_struct.h"
#include "main/dll/sbkytecagestate_struct.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/sbcloudballstate_struct.h"

extern u8 framesThisStep;

extern void objRenderFn_8003b8f4(f32);

#include "main/game_object.h"
#include "main/dll/TREX/TREX_trex.h"

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

extern f32 lbl_803E59A8;
extern f32 lbl_803E5998;
extern f32 lbl_803E599C;
extern f32 lbl_803E59AC;
extern f32 lbl_803E59B0;

void FUN_801e55c0(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined2* param_9, int param_10)
{
}

void SB_FireBall_release(void);

void Flag_free(void)
{
}

void Flag_hitDetect(void)
{
}

void Flag_release(void)
{
}

void Flag_initialise(void)
{
}

void SB_ShipGunBroke_free(void);

int Flag_getExtraSize(void) { return 0x0; }
int Flag_getObjectTypeId(void) { return 0x0; }
int SB_ShipGunBroke_getExtraSize(void);

void Flag_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E59A8);
}


/* Stubs added to align function set with v1.0 asm. Source had Ghidra FUN_xxx
 * splits at wrong addresses; these stubs ensure every asm symbol has a src
 * definition so future hunters can fill bodies one at a time. */
void Flag_init(int* obj, int* def)
{
    if (((GameObject*)obj)->anim.seqId != 0x803)
    {
        ((GameObject*)obj)->anim.rotX = (s16)((s32) * (s8*)((char*)def + 0x18) << 8);
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E5998, 0);
    }
}

void Flag_update(int obj)
{
    extern void* Obj_GetPlayerObject(void);
    int linkedObj;

    if (((GameObject*)obj)->anim.seqId == 0x187)
    {
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E59AC,
                                                                     (f32)(u32)framesThisStep,
                                                                     NULL);
    }
    else if (((GameObject*)obj)->anim.seqId == 0x803)
    {
        Obj_GetPlayerObject();
        linkedObj = *(int*)&((GameObject*)obj)->anim.parent;
        if ((((GameObject*)linkedObj)->objectFlags & 0x1000) != 0)
        {
            ((GameObject*)obj)->anim.velocityX = lbl_803E5998;
        }
        else
        {
            ((GameObject*)obj)->anim.velocityX = (f32)((GameObject*)linkedObj)->anim.rotZ * lbl_803E599C;
            ((GameObject*)obj)->anim.rotZ = (s16)(
                (f32)((GameObject*)obj)->anim.rotZ + ((GameObject*)obj)->anim.velocityX);
        }
    }
    else
    {
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E59B0,
                                                                     (f32)(u32)framesThisStep,
                                                                     NULL);
    }
}

int SB_KyteCage_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

/* EN v1.0 0x801E4F14  size: 60b  Decrement obj->_f4 if > 0, OR in bit 0x8
 * of obj->_af, latch state->_6e = -2 and state->_56 = 0; return 0. */

/* EN v1.0 0x801E4BA4  size: 48b  When obj->_b8->[0] is non-null,
 * call ObjLink_DetachChild(obj). */

/* EN v1.0 0x801E60A4  size: 28b  shop state reset/seed: zero obj->_b8[2]
 * and obj->_b8[3], stash (s8)v in obj->_b8[4]. */

/* EN v1.0 0x801E607C  size: 40b  Increment-and-store: obj->_b8[2] += p3,
 * obj->_b8[3] += p2. */

/* EN v1.0 0x801E6050  size: 44b  Triple s8 fan-out: write obj->_b8[2/3/4]
 * (sign-extended) into *out_b3, *out_b2, *out_b4. */

/* EN v1.0 0x801E6358  size: 104b  Returns 1 unless the item's
 * "available" GameBit gate (lbl_80327FD0[idx*12 + 6]) is present and
 * unset.  (i.e. open by default, gated when slot != -1.) */

/* EN v1.0 0x801E62F0  size: 104b  Returns 1 when shop item's "bought"
 * GameBit (slot at lbl_80327FD0[idx*12 + 8]) is set; else 0. */
