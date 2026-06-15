/* DLL 0x0111 — door-lock objects [8017AC2C-8017ADB4) */
#include "main/game_object.h"
#include "main/dll/doorlockstate_struct.h"

extern undefined8 ObjGroup_RemoveObject();

#include "main/dll/cfguardian_state.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/cfguardian.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/dll/alphaanim.h"
#include "main/objanim_internal.h"

typedef struct LockDoorLockPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
    u8 unk20;
    u8 unk21;
    s16 unk22;
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} LockDoorLockPlacement;

typedef struct DoorlockPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 unk22;
    s16 unk24;
    s16 unk26;
} DoorlockPlacement;

extern undefined4 ObjGroup_AddObject();

extern u32 GameBit_Get(int eventId);

__declspec(section ".sdata") extern char lbl_803DBD90[];

extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E3798;
extern void objRenderFn_80041018(int* obj);
extern int ObjTrigger_IsSetById(int obj, int id);
extern int ObjTrigger_IsSet(int obj);
extern void buttonDisable(int index, int mask);
extern uint GameBit_Get(int eventId);

int doorlock_getExtraSize(void) { return 0x1; }

void doorlock_free(int x) { ObjGroup_RemoveObject(x, 0xf); }

void mmp_bridge_init(int* obj);

void doorlock_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        if (obj[0xf8 / 4] == 0)
        {
            goto render_basic;
        }
    }
    if (obj[0xf8 / 4] == 0)
    {
        return;
    }
    objRenderFn_80041018(obj);
    return;

render_basic:
    ((void(*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E3798);
}

int Door_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

int Door_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

int Lock_DoorLock_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern int GameBit_Set(int eventId, int value); /* #57 */
    int def;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    if (animUpdate->triggerCommand != 0)
    {
        if (((*(u8*)(def + 0x1b) & 4) != 0) && (animUpdate->triggerCommand == 1))
        {
            GameBit_Set(((LockDoorLockPlacement*)def)->unk1C, 1);
        }
        if ((animUpdate->triggerCommand == 2) && (((LockDoorLockPlacement*)def)->unk24 != 0))
        {
            (*gObjectTriggerInterface)->yield((ObjSeqState*)animUpdate, ((LockDoorLockPlacement*)def)->unk24);
        }
        animUpdate->triggerCommand = 0;
    }
    ((GameObject*)obj)->unkF8 = 0;
    return 0;
}

void doorlock_update(int obj)
{
    extern int GameBit_Set(int eventId, int value); /* #57 */
    int state;
    int def;
    int flags;
    u8 b;

    state = *(int*)&((GameObject*)obj)->extra;
    def = *(int*)&((GameObject*)obj)->anim.placementData;
    if (((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0) && (GameBit_Get(0x930) == 0))
    {
        buttonDisable(0, 0x100);
        (*gObjectTriggerInterface)->setRunSequenceWorldSpace(obj, 0);
        (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
        GameBit_Set(0x930, 1);
    }
    else
    {
        *(u8*)state = GameBit_Get(((DoorlockPlacement*)def)->unk1C);
        if ((*(u8*)(def + 0x1b) & 1) != 0)
        {
            if (*(u8*)state != 0)
            {
                ((GameObject*)obj)->anim.alpha = 0;
            }
        }
        else if ((((DoorlockPlacement*)def)->unk26 & 1) != 0)
        {
            if (*(u8*)state != 0)
            {
                ((GameObject*)obj)->unkF8 = 0;
            }
            else
            {
                ((GameObject*)obj)->unkF8 = 1;
            }
        }
        if (*(u8*)state == 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x10;
            if ((((DoorlockPlacement*)def)->unk22 != -1) && (GameBit_Get(((DoorlockPlacement*)def)->unk22) == 0))
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
                if ((*(u8*)(def + 0x1b) & 0x10) != 0)
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
                }
            }
            if ((((DoorlockPlacement*)def)->unk1E != -1) && (GameBit_Get(((DoorlockPlacement*)def)->unk1E) == 0))
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
            }
            if (((((DoorlockPlacement*)def)->unk1E != -1) && (ObjTrigger_IsSetById(
                    obj, ((DoorlockPlacement*)def)->unk1E) != 0)) ||
                ((((DoorlockPlacement*)def)->unk1E == -1) && (ObjTrigger_IsSet(obj) != 0)))
            {
                if (*(s8*)(def + 0x20) != -1)
                {
                    (*gObjectTriggerInterface)->runSequence((int)*(s8*)(def + 0x20), (void*)obj, -1);
                }
                if ((*(u8*)(def + 0x1b) & 4) == 0)
                {
                    GameBit_Set(((DoorlockPlacement*)def)->unk1C, 1);
                }
                if ((*(u8*)(def + 0x1b) & 8) != 0)
                {
                    GameBit_Set(((DoorlockPlacement*)def)->unk22, 0);
                }
                else
                {
                    *(u8*)state = 1;
                    ((GameObject*)obj)->unkF4 = 1;
                }
                buttonDisable(0, 0x100);
            }
        }
        else
        {
            if (((GameObject*)obj)->unkF4 == 0)
            {
                if ((*(s8*)(def + 0x20) != -1) && (((DoorlockPlacement*)def)->unk24 != 0))
                {
                    (*gObjectTriggerInterface)->preempt(obj, ((DoorlockPlacement*)def)->unk24);
                    flags = 1;
                    b = *(u8*)(def + 0x1b);
                    if ((b & 0x20) != 0)
                    {
                        flags |= 2;
                    }
                    if ((b & 0x40) != 0)
                    {
                        flags |= 4;
                    }
                    if ((b & 0x80) != 0)
                    {
                        flags |= 8;
                    }
                    (*gObjectTriggerInterface)->runSequence((int)*(s8*)(def + 0x20), (void*)obj, flags);
                }
                ((GameObject*)obj)->unkF4 = 1;
            }
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        }
        if (((((ObjAnimComponent*)obj)->modelInstance->flags & 1) != 0) &&
            (((ObjAnimComponent*)obj)->hitVolumeTransforms != NULL))
        {
            objRenderFn_80041018((int*)obj);
        }
    }
}

/* segment pragma-stack balance (re-split): */

void doorlock_init(short* obj, DoorLockPlacement* config)
{
    ObjAnimComponent* objAnim;
    DoorLockState* state;

    objAnim = (ObjAnimComponent*)obj;
    *obj = (short)((byte)config->rotXByte << 8);
    ((GameObject*)obj)->anim.rotY = (short)((byte)config->rotYByte << 8);
    ((GameObject*)obj)->anim.rotZ = (short)((byte)config->rotZByte << 8);
    ((GameObject*)obj)->animEventCallback = (void*)Lock_DoorLock_SeqFn;
    *(u8*)&objAnim->bankIndex = config->modelBankIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    state = ((GameObject*)obj)->extra;
    state->unlocked = (byte)GameBit_Get(config->lockGameBit);
    ObjGroup_AddObject(obj, 0xf);
    if ((config->flags & 1) != 0)
    {
        if (state->unlocked != 0)
        {
            objAnim->alpha = 0;
        }
    }
    else if ((config->modeFlags & 1) != 0)
    {
        if (state->unlocked != 0)
        {
            ((GameObject*)obj)->unkF8 = 0;
        }
        else
        {
            ((GameObject*)obj)->unkF8 = 1;
        }
    }
    return;
}

undefined4 FUN_8017c608(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10 , ObjAnimUpdateState* animUpdate, undefined4 param_12, int param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16);

/* immultiseq_SeqFn: seqobj2 advance-state predicate. If obj has a trigger id
 * (-1 sentinel skips), peek at the next state slot in def[0x20+n*2], read
 * its GameBit, compare against the def[0x30] mask bit for that slot, and
 * if the polarity flips (GameBit != mask bit) end the current sequence.
 * Always latches state[1] bit 0 before returning 0. */
