/* DLL 0x0110 — door objects [8017AC2C-8017ADB4) */
#include "main/game_object.h"

extern undefined8 ObjGroup_RemoveObject();

/*
 * --INFO--
 *
 * Function: pressureswitchfb_updateStateMode
 * EN v1.0 Address: 0x8017AC2C
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x8017AC40
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: pressureswitchfb_getExtraSize
 * EN v1.0 Address: 0x8017AD88
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8017ADC4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: pressureswitchfb_free
 * EN v1.0 Address: 0x8017AD90
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017ADCC
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

#include "main/dll/cfguardian_state.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/cfguardian.h"
#include "main/game_object.h"
#include "main/objseq.h"

typedef struct DoorObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    u8 unk1C;
    u8 unk1D;
    u8 pad1E[0x20 - 0x1E];
    u8 unk20;
    u8 unk21;
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} DoorObjectDef;

typedef struct DoorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    u8 unk1E;
    u8 pad1F[0x20 - 0x1F];
    s16 unk20;
    s16 unk22;
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} DoorPlacement;

extern undefined4 ObjHits_DisableObject();

extern ObjectTriggerInterface** gObjectTriggerInterface;

/*
 * --INFO--
 *
 * Function: pressureswitchfb_update
 * EN v1.0 Address: 0x8017ADB4
 * EN v1.0 Size: 1540b
 * EN v1.1 Address: 0x8017B2F8
 * EN v1.1 Size: 1604b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

extern int* objFindTexture(int* obj, int a, int b);
extern u32 GameBit_Get(int eventId);
extern int Sfx_PlayFromObject(int obj, int sfxId);

/*
 * --INFO--
 *
 * Function: FUN_8017b3bc
 * EN v1.0 Address: 0x8017B3BC
 * EN v1.0 Size: 768b
 * EN v1.1 Address: 0x8017BB20
 * EN v1.1 Size: 796b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_8017b6bc
 * EN v1.0 Address: 0x8017B6BC
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8017BE3C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_8017b6dc
 * EN v1.0 Address: 0x8017B6DC
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x8017BE60
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_8017b7a8
 * EN v1.0 Address: 0x8017B7A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017BF24
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_8017b7ac
 * EN v1.0 Address: 0x8017B7AC
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x8017C0F4
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/* Trivial 4b 0-arg blr leaves. */

__declspec(section ".sdata") extern char lbl_803DBD90[];

/* 8b "li r3, N; blr" returners. */
int Door_getExtraSize(void) { return 0x8; }
int mmp_bridge_getExtraSize(void);

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E3780;
extern void objRenderFn_8003b8f4(f32);
void Door_render(void) { objRenderFn_8003b8f4(lbl_803E3780); }

/* ObjGroup_RemoveObject(x, N) wrappers. */
void doorlock_free(int x);

int Door_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
extern f32 lbl_803E3784;
extern f32 lbl_803E3788;
extern f32 lbl_803E3790;

void Door_init(int* obj, u8* def)
{
    u8* state = ((GameObject*)obj)->extra;
    state[5] = 1;
    *(s16*)obj = (s16)(def[0x1f] << 8);
    ((GameObject*)obj)->animEventCallback = (void*)Door_SeqFn;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x2000);
    ((GameObject*)obj)->anim.rootMotionScale = ((f32)(u32)((DoorObjectDef*)def)->unk21 - lbl_803E3790) * lbl_803E3784;
    if (((GameObject*)obj)->anim.rootMotionScale == lbl_803E3788)
    {
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3780;
    }
    ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * *(f32*)(*(int*)&((GameObject*)
        obj)->anim.modelInstance + 4);
    if (((DoorObjectDef*)def)->unk1A != -1)
    {
        state[4] = (u8)GameBit_Get(((DoorObjectDef*)def)->unk1A);
    }
    else
    {
        state[4] = 0;
    }
    state[6] = 0;
    if (GameBit_Get(((DoorObjectDef*)def)->unk18) != 0) state[6] = (u8)(state[6] | 1);
    if (GameBit_Get(((DoorObjectDef*)def)->unk22) != 0) state[6] = (u8)(state[6] | 2);
    {
        s16 model = ((GameObject*)obj)->anim.seqId;
        switch (model)
        {
        case 1101:
            {
                s32 subtype = ((GameObject*)obj)->anim.mapEventSlot;
                if ((subtype < 35 && subtype >= 31) || (subtype < 43 && subtype >= 40))
                {
                    *(s16*)state = 832;
                    *(s16*)&((CfGuardianState*)state)->sfxId = 833;
                }
                else
                {
                    *(s16*)state = 1154;
                    *(s16*)&((CfGuardianState*)state)->sfxId = 1155;
                }
                break;
            }
        case 358:
            *(s16*)state = 275;
            *(s16*)&((CfGuardianState*)state)->sfxId = 504;
            break;
        }
    }
}

void Door_update(int obj)
{
    int state;
    int def;
    int triggerArg;
    int triggerId;

    state = *(int*)&((GameObject*)obj)->extra;
    def = *(int*)&((GameObject*)obj)->anim.placementData;
    if (*(u8*)(state + 5) != 0)
    {
        triggerId = ((DoorPlacement*)def)->unk1C;
        if ((triggerId != 0) && (*(u8*)(state + 4) != 0))
        {
            triggerArg = *(u8*)(def + 0x20) & 0x7f;
            (*gObjectTriggerInterface)->preempt(obj, triggerId);
        }
        else
        {
            triggerArg = -1;
        }
        if (*(s8*)&((DoorPlacement*)def)->unk1E != -1)
        {
            (*gObjectTriggerInterface)->runSequence((int)*(s8*)&((DoorPlacement*)def)->unk1E, (void*)obj, triggerArg);
        }
        *(u8*)(state + 5) = 0;
    }
}

void mmp_bridge_update(int* obj);

extern int Sfx_IsPlayingFromObject(int obj, int sfxId);
extern int Sfx_StopFromObject(int obj, int sfxId);

/*
 * --INFO--
 *
 * Function: Door_SeqFn
 * EN v1.0 Address: 0x8017B5C8
 * EN v1.0 Size: 788b
 */
int Door_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern int GameBit_Set(int eventId, int value); /* #57 */
    int i;
    int state;
    int def;
    int opened;
    int closeReady;
    int* tex;
    int ret;

    state = *(int*)&((GameObject*)obj)->extra;
    def = *(int*)&((GameObject*)obj)->anim.placementData;
    if (((GameObject*)obj)->anim.alpha == 0)
    {
        ObjHits_DisableObject(obj);
    }
    if (*(u8*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x59) != 0)
    {
        if ((*(u8*)(state + 6) & 1) != 0)
        {
            tex = (int*)objFindTexture((int*)obj, 0, 0);
            if (tex != NULL)
            {
                *tex = 0x100;
            }
        }
        if ((*(u8*)(state + 6) & 2) != 0)
        {
            tex = (int*)objFindTexture((int*)obj, 1, 0);
            if (tex != NULL)
            {
                *tex = 0x100;
            }
        }
    }
    if (*(u8*)(state + 4) == 0)
    {
        opened = GameBit_Get(((DoorPlacement*)def)->unk18);
        closeReady = 0;
        if ((((DoorPlacement*)def)->unk22 == -1) || (GameBit_Get(((DoorPlacement*)def)->unk22) != 0))
        {
            closeReady = 1;
        }
        if ((opened != 0) && ((*(u8*)(state + 6) & 1) == 0))
        {
            if (*(u8*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x59) != 0)
            {
                Sfx_PlayFromObject(obj, 0x4b);
            }
            *(u8*)(state + 6) |= 1;
        }
        if ((closeReady != 0) && ((*(u8*)(state + 6) & 2) == 0))
        {
            if (*(u8*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x59) != 0)
            {
                Sfx_PlayFromObject(obj, 0x4b);
            }
            *(u8*)(state + 6) |= 2;
        }
        if (*(u8*)(state + 6) == 3)
        {
            *(u8*)(state + 4) = 2;
            if (*(u16*)state != 0)
            {
                Sfx_PlayFromObject(obj, *(u16*)state);
            }
        }
    }
    else if (*(u8*)(state + 4) == 1)
    {
        if (GameBit_Get(((DoorPlacement*)def)->unk18) == 0)
        {
            *(u8*)(state + 4) = 3;
            if (*(u16*)state != 0)
            {
                Sfx_PlayFromObject(obj, *(u16*)state);
            }
        }
    }
    if (*(u8*)(state + 4) == 2)
    {
        for (i = 0; i < animUpdate->eventCount; i++)
        {
            if (animUpdate->eventIds[i] == 2)
            {
                *(u8*)(state + 4) = 1;
                if (((DoorPlacement*)def)->unk1A != -1)
                {
                    GameBit_Set(((DoorPlacement*)def)->unk1A, 1);
                }
                if ((*(u16*)state != 0) && (Sfx_IsPlayingFromObject(obj, *(u16*)state) != 0))
                {
                    Sfx_StopFromObject(obj, *(u16*)state);
                }
                if (((CfGuardianState*)state)->sfxId != 0)
                {
                    Sfx_PlayFromObject(obj, ((CfGuardianState*)state)->sfxId);
                }
            }
        }
    }
    else if (*(u8*)(state + 4) == 3)
    {
        for (i = 0; i < animUpdate->eventCount; i++)
        {
            if (animUpdate->eventIds[i] == 1)
            {
                *(u8*)(state + 4) = 0;
                *(u8*)(state + 6) = 0;
                if (((DoorPlacement*)def)->unk1A != -1)
                {
                    GameBit_Set(((DoorPlacement*)def)->unk1A, 0);
                }
                if ((*(u16*)state != 0) && (Sfx_IsPlayingFromObject(obj, *(u16*)state) != 0))
                {
                    Sfx_StopFromObject(obj, *(u16*)state);
                }
                if (((CfGuardianState*)state)->sfxId != 0)
                {
                    Sfx_PlayFromObject(obj, ((CfGuardianState*)state)->sfxId);
                }
            }
        }
    }
    ret = 0;
    if ((*(u8*)(state + 4) != 2) && (*(u8*)(state + 4) != 3))
    {
        ret = 1;
    }
    return ret;
}

/*
 * --INFO--
 *
 * Function: Lock_DoorLock_SeqFn
 * EN v1.0 Address: 0x8017BCF8
 * EN v1.0 Size: 180b
 */
int Lock_DoorLock_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

/*
 * --INFO--
 *
 * Function: doorlock_update
 * EN v1.0 Address: 0x8017BE28
 * EN v1.0 Size: 848b
 */

/* segment pragma-stack balance (re-split): */

#include "main/dll/alphaanim.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"

extern uint GameBit_Get(int eventId);

/*
 * --INFO--
 *
 * Function: doorlock_init
 * EN v1.0 Address: 0x8017C178
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x8017C250
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_8017c5c4
 * EN v1.0 Address: 0x8017C5C4
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x8017C7EC
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_8017c608
 * EN v1.0 Address: 0x8017C608
 * EN v1.0 Size: 456b
 * EN v1.1 Address: 0x8017C82C
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObject_free
 * EN v1.0 Address: 0x8017C7D0
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017C960
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObject_render
 * EN v1.0 Address: 0x8017C7F4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8017C984
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObject_update
 * EN v1.0 Address: 0x8017C81C
 * EN v1.0 Size: 548b
 * EN v1.1 Address: 0x8017C9B4
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObject_init
 * EN v1.0 Address: 0x8017CA40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017CC04
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObj2_free
 * EN v1.0 Address: 0x8017CAF4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017CDE4
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObj2_update
 * EN v1.0 Address: 0x8017CB18
 * EN v1.0 Size: 460b
 * EN v1.1 Address: 0x8017CE10
 * EN v1.1 Size: 596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: seqObj2_init
 * EN v1.0 Address: 0x8017CCE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017D064
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/* Trivial 4b 0-arg blr leaves. */

/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */

/* ObjGroup_RemoveObject(x, N) wrappers. */

/* Drift-recovery: add new fns with v1.0 names. */

/* immultiseq_SeqFn: seqobj2 advance-state predicate. If obj has a trigger id
 * (-1 sentinel skips), peek at the next state slot in def[0x20+n*2], read
 * its GameBit, compare against the def[0x30] mask bit for that slot, and
 * if the polarity flips (GameBit != mask bit) end the current sequence.
 * Always latches state[1] bit 0 before returning 0. */
