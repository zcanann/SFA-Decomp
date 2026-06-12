/* DLL 0x01F1 — SB sequential-door objects [801E4288-801E42F8) */
#include "main/dll_000A_expgfx.h"
#include "main/dll/shipbattlestate_struct.h"
#include "main/dll/sbkytecagestate_struct.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/sbcloudballstate_struct.h"
#include "main/dll/TREX/TREX_levelcontrol.h"

/* Trivial 4b 0-arg blr leaves. */

/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */
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

typedef struct SBSeqDoorObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    s8 unk19;
    u8 unk1A;
    u8 pad1B[0x20 - 0x1B];
} SBSeqDoorObjectDef;

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

extern ObjectTriggerInterface** gObjectTriggerInterface;

void FUN_801e55c0(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined2* param_9, int param_10)
{
}

/* Trivial 4b 0-arg blr leaves. */
void SB_FireBall_release(void);

void SB_SeqDoor_free(void)
{
}

void SB_SeqDoor_hitDetect(void)
{
}

void SB_SeqDoor_release(void)
{
}

void SB_SeqDoor_initialise(void)
{
}

void SB_MiniFire_hitDetect(void);

/* 8b "li r3, N; blr" returners. */
int SB_SeqDoor_getExtraSize(void) { return 0x0; }
int SB_SeqDoor_getObjectTypeId(void) { return 0x0; }
int SB_MiniFire_getExtraSize(void);

/* 16b chained patterns. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5920;
extern int GameBit_Get(int);
int SB_SeqDoor_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

void SB_SeqDoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5920);
}

void Lamp_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* Stubs added to align function set with v1.0 asm. Source had Ghidra FUN_xxx
 * splits at wrong addresses; these stubs ensure every asm symbol has a src
 * definition so future hunters can fill bodies one at a time. */

/* EN v1.0 0x801E4F14  size: 60b  Decrement obj->_f4 if > 0, OR in bit 0x8
 * of obj->_af, latch state->_6e = -2 and state->_56 = 0; return 0. */

int SB_SeqDoor_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    if (((GameObject*)obj)->anim.seqId != 0x173)
    {
        animUpdate->hitVolumePair = -2;
    }
    animUpdate->sequenceEventActive = 0;
    return 0;
}

extern f32 lbl_803E597C;

/* EN v1.0 0x801E4BA4  size: 48b  When obj->_b8->[0] is non-null,
 * call ObjLink_DetachChild(obj). */

void SB_SeqDoor_init(int* obj, int* def)
{
    ((GameObject*)obj)->animEventCallback = (void*)SB_SeqDoor_SeqFn;
    *(s16*)obj = (s16)((s32)((SBSeqDoorObjectDef*)def)->unk18 << 8);
    {
        s8 b = ((SBSeqDoorObjectDef*)def)->unk19;
        ((ObjAnimComponent*)obj)->bankIndex = (s8)(((u32) - b | (u32)b) >> 31);
    }
}

void SB_SeqDoor_update(int* obj)
{
    if (((GameObject*)obj)->anim.seqId == 371)
    {
        if (((GameObject*)obj)->unkF4 == 0)
        {
            if ((u32)GameBit_Get(2635) != 0u)
            {
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                ((GameObject*)obj)->unkF4 = 1;
            }
        }
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
}

extern f32 lbl_803E59C0;

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
