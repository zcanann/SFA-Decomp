/* DLL 0x01F7 — sbshipgunbroke / SB_ShipGun group. TU: 0x801E4288–0x801E42F8. */
#include "main/dll_000A_expgfx.h"
#include "main/dll/shipbattlestate_struct.h"
#include "main/dll/sbkytecagestate_struct.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/sbcloudballstate_struct.h"
#include "main/dll/TREX/TREX_levelcontrol.h"

extern void objRenderFn_8003b8f4(f32);

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

typedef struct SBShipGunBrokePlacement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
} SBShipGunBrokePlacement;

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

void FUN_801e55c0(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined2* param_9, int param_10)
{
}

void SB_FireBall_release(void);

void SB_ShipGunBroke_free(void)
{
}

void SB_ShipGunBroke_hitDetect(void)
{
}

void SB_ShipGunBroke_init(void)
{
}

void SB_ShipGunBroke_release(void)
{
}

void SB_ShipGunBroke_initialise(void)
{
}

void shop_hitDetect(void);

int SB_ShipGunBroke_getExtraSize(void) { return 0x1; }
int SB_ShipGunBroke_getObjectTypeId(void) { return 0x0; }
int shop_getExtraSize(void);

extern int GameBit_Get(int);

/* Stubs added to align function set with v1.0 asm. Source had Ghidra FUN_xxx
 * splits at wrong addresses; these stubs ensure every asm symbol has a src
 * definition so future hunters can fill bodies one at a time. */

/* EN v1.0 0x801E4F14  size: 60b  Decrement obj->_f4 if > 0, OR in bit 0x8
 * of obj->_af, latch state->_6e = -2 and state->_56 = 0; return 0. */

/* EN v1.0 0x801E4BA4  size: 48b  When obj->_b8->[0] is non-null,
 * call ObjLink_DetachChild(obj). */

extern f32 lbl_803E59C0;

void SB_ShipGunBroke_render(int* obj, int p2, int p3, int p4, int p5)
{
    int* p = *(int**)&((GameObject*)obj)->anim.placementData;
    if ((u32)GameBit_Get(((SBShipGunBrokePlacement*)p)->unk1E) != 0u)
    {
        ((void(*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E59C0);
    }
}

void SB_ShipGunBroke_update(int* obj)
{
    extern void Sfx_PlayFromObject(int* obj, int sfxId);
    int* p = *(int**)&((GameObject*)obj)->anim.placementData;
    if ((u32)GameBit_Get(((SBShipGunBrokePlacement*)p)->unk1E) != 0u)
    {
        Sfx_PlayFromObject(obj, SFXen_nlite1_c);
    }
}

void ShipBattle_free(int* obj);

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
