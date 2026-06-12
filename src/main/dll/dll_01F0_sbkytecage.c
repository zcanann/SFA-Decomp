/* DLL 0x1F0 — SB kyte cage / ship battle objects [801E4288-801E42F8) */
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



extern f32 timeDelta;






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


extern undefined4 getLActions();
extern undefined4 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();

extern ObjectTriggerInterface** gObjectTriggerInterface;

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




void SB_KyteCage_render(void)
{
}

void SB_KyteCage_hitDetect(void)
{
}

void SB_KyteCage_release(void)
{
}

void SB_KyteCage_initialise(void)
{
}

void SB_CageKyte_free(void);


























/* 8b "li r3, N; blr" returners. */
int SB_KyteCage_getExtraSize(void) { return 0x8; }
int SB_KyteCage_getObjectTypeId(void) { return 0x0; }
int SB_CageKyte_getExtraSize(void);

/* 16b chained patterns. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern int GameBit_Get(int);
extern void GameBit_Set(int slot, int val);
extern f32 lbl_803E5918;






/* Stubs added to align function set with v1.0 asm. Source had Ghidra FUN_xxx
 * splits at wrong addresses; these stubs ensure every asm symbol has a src
 * definition so future hunters can fill bodies one at a time. */


int SB_KyteCage_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern void Sfx_PlayFromObject(int* obj, int sfxId);
    int i;
    int state;

    i = 0;
    state = *(int*)&((GameObject*)obj)->extra;
    while (i < animUpdate->eventCount)
    {
        u8 seqCode;

        seqCode = animUpdate->eventIds[i];
        if (seqCode == 1)
        {
            *(u8*)(state + 4) = 1;
        }
        else if (seqCode == 2)
        {
            *(u8*)(state + 4) = 2;
        }
        i++;
    }

    animUpdate->hitVolumePair = -4;
    if (((GameObject*)obj)->seqIndex != -1)
    {
        animUpdate->hitVolumePair &= ~4;
        if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E5918,
                                                                         timeDelta, NULL) != 0)
        {
            Sfx_PlayFromObject((int*)obj, SFXfend_rob_beep2);
        }
    }

    animUpdate->sequenceEventActive = 0;
    return 0;
}

/* EN v1.0 0x801E4F14  size: 60b  Decrement obj->_f4 if > 0, OR in bit 0x8
 * of obj->_af, latch state->_6e = -2 and state->_56 = 0; return 0. */
int SB_CageKyte_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);




















/* EN v1.0 0x801E4BA4  size: 48b  When obj->_b8->[0] is non-null,
 * call ObjLink_DetachChild(obj). */
void SB_KyteCage_free(int* obj)
{
    void* child = (*(SBKyteCageState**)&((GameObject*)obj)->extra)->kyte;
    if (child != NULL)
    {
        ObjLink_DetachChild(obj, child);
    }
}

void SB_KyteCage_init(int* obj, int* params)
{
    SBKyteCageState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)SB_KyteCage_SeqFn;
    *(s16*)obj = (s16)((s8) * (s8*)&((ObjHitsPriorityState*)params)->localPosZ << 8);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
    state->seqLatch = 0;
    if ((u32)GameBit_Get(117) == 0u)
    {
        getLActions(obj, obj, 88, 0, 0, 0);
        getLActions(obj, obj, 109, 0, 0, 0);
    }
}

extern void buttonDisable(int controller, int mask);
extern int* objModelGetVecFn_800395d8(int obj, int idx);
extern f32 lbl_803E591C;

void SB_KyteCage_update(int obj)
{
    extern int* ObjList_GetObjects(int* out_head, int* out_count);
    extern void Sfx_PlayFromObject(int* obj, int sfxId);
    extern uint GameBit_Get(int);
    SBKyteCageState* state = ((GameObject*)obj)->extra;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x8);
    if (state->kyte == NULL)
    {
        int* head;
        int count;
        int i;
        head = ObjList_GetObjects(&i, &count);
        for (i = 0; i < count; i++)
        {
            int child = head[i];
            if (*(s16*)(child + 0x46) == 0x121)
            {
                *(int*)&state->kyte = child;
                ObjLink_AttachChild(obj, *(int*)&state->kyte, 1);
                i = count;
            }
        }
    }
    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
    {
        if (GameBit_Get(0x92a) == 0)
        {
            buttonDisable(0, 0x100);
            (*gObjectTriggerInterface)->setRunSequenceWorldSpace(obj, 0);
            (*gObjectTriggerInterface)->runSequence(3, (void*)obj, -1);
            GameBit_Set(0x92a, 1);
            return;
        }
    }
    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0)
    {
        buttonDisable(0, 0x100);
        (*gObjectTriggerInterface)->setRunSequenceWorldSpace(obj, 0);
        if (state->doorChoice != 0)
        {
            (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
        }
        else
        {
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
            state->doorChoice = 1;
        }
    }
    if (((GameObject*)obj)->anim.parent != NULL)
    {
        int kind = *(int*)(*(int*)&((GameObject*)obj)->anim.parent + 0xf4);
        int* mvec = objModelGetVecFn_800395d8(obj, 0);
        if (mvec != 0 && kind < 9 && ((GameObject*)obj)->anim.currentMove != 5)
        {
            *(s16*)((char*)mvec + 4) = *(s16*)(*(int*)&((GameObject*)obj)->anim.parent + 4);
            ObjAnim_SetCurrentMove(obj, 5, lbl_803E591C, 0);
        }
        else if (mvec != 0 && kind >= 9 && ((GameObject*)obj)->anim.currentMove != 9)
        {
            *(s16*)((char*)mvec + 4) = 0;
            ObjAnim_SetCurrentMove(obj, 9, lbl_803E591C, 0);
        }
    }
    if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E5918,
                                                                     timeDelta, NULL) != 0)
    {
        Sfx_PlayFromObject((int*)obj, SFXfend_rob_beep2);
    }
}

void SB_MiniFire_free(int* obj);



















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


