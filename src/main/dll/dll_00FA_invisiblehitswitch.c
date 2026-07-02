/* DLL 0x00FA (invisiblehitswitch) — Invisible hit switch object [0x8017A8EC-0x8017AC2C). */
#include "main/dll/tFrameAnimator.h"
#include "main/objlib.h"

int area_getExtraSize(void);
int area_getObjectTypeId(void);

void area_free(void);

void area_render(void);

void area_hitDetect(void);

void area_update(void);

void area_init(u16* obj);

void area_release(void);

void area_initialise(void);

extern u8 framesThisStep;

ObjectDescriptor gAreaObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)area_initialise,
    (ObjectDescriptorCallback)area_release,
    0,
    (ObjectDescriptorCallback)area_init,
    (ObjectDescriptorCallback)area_update,
    (ObjectDescriptorCallback)area_hitDetect,
    (ObjectDescriptorCallback)area_render,
    (ObjectDescriptorCallback)area_free,
    (ObjectDescriptorCallback)area_getObjectTypeId,
    area_getExtraSize,
};

#include "main/game_object.h"
#include "main/gamebits.h"

typedef struct InvisibleHitSwitchPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 gameBitId;
    s16 cooldownFrames;
    u8 pad1C[0x1E - 0x1C];
    u8 triggerMode;
    u8 pad1F[0x20 - 0x1F];
} InvisibleHitSwitchPlacement;

typedef struct InvisibleHitSwitchState
{
    u8 active;
    u8 hitId;
    u8 pad2[0x4 - 0x2];
    f32 cooldownTimer;
    f32 activationTimer;
    u8 padC[0x20 - 0xC];
    u8 unk20;
    u8 unk21;
    u8 unk22;
    u8 unk23;
    u8 pad24[0x28 - 0x24];
} InvisibleHitSwitchState;

extern f32 timeDelta;
extern const f32 lbl_803E3730;
extern f32 lbl_803E3734;
extern f32 lbl_803E3738;
extern f32 lbl_803E373C;
extern f32 lbl_803E3750;

int InvisibleHitSwitch_getExtraSize(void) { return 0xc; }

void InvisibleHitSwitch_update(int obj)
{

    int state2;
    int state;
    int hitId;

    state2 = *(int*)&((GameObject*)obj)->anim.placementData;
    state = *(int*)&((GameObject*)obj)->extra;
    if (((InvisibleHitSwitchState*)state)->active != 0)
    {
        if (GameBit_Get((int)((InvisibleHitSwitchPlacement*)state2)->gameBitId) == 0)
        {
            ((InvisibleHitSwitchState*)state)->active = 0;
        }
    }
    else
    {
        if (GameBit_Get((int)((InvisibleHitSwitchPlacement*)state2)->gameBitId) != 0)
        {
            ((InvisibleHitSwitchState*)state)->active = 1;
        }
    }

    if (((InvisibleHitSwitchState*)state)->cooldownTimer > lbl_803E3730)
    {
        ((InvisibleHitSwitchState*)state)->cooldownTimer =
            ((InvisibleHitSwitchState*)state)->cooldownTimer - (f32)(u32)
        framesThisStep;
        if (((InvisibleHitSwitchState*)state)->cooldownTimer <= lbl_803E3730)
        {
            ((InvisibleHitSwitchState*)state)->cooldownTimer = lbl_803E3730;
            GameBit_Set((int)((InvisibleHitSwitchPlacement*)state2)->gameBitId, 0);
        }
        else
        {
            return;
        }
    }

    if (((InvisibleHitSwitchState*)state)->activationTimer != *(f32*)&lbl_803E3730)
    {
        ((InvisibleHitSwitchState*)state)->activationTimer = ((InvisibleHitSwitchState*)state)->activationTimer - timeDelta;
        if (((InvisibleHitSwitchState*)state)->activationTimer < lbl_803E3734)
        {
            hitId = ObjHits_GetPriorityHit(obj, 0, 0, 0);
            if ((int)((InvisibleHitSwitchState*)state)->hitId == hitId)
            {
                ((InvisibleHitSwitchState*)state)->activationTimer = lbl_803E3730;
                ((InvisibleHitSwitchState*)state)->active = 1;
                GameBit_Set((int)((InvisibleHitSwitchPlacement*)state2)->gameBitId, 1);
            }
            else if (((InvisibleHitSwitchState*)state)->activationTimer <= *(f32*)&lbl_803E3730)
            {
                ((InvisibleHitSwitchState*)state)->activationTimer = lbl_803E3730;
            }
        }
    }
    else
    {
        hitId = ObjHits_GetPriorityHit(obj, 0, 0, 0);
        if ((int)((InvisibleHitSwitchState*)state)->hitId != hitId) return;
        if (((InvisibleHitSwitchState*)state)->active != 0)
        {
            if ((((InvisibleHitSwitchPlacement*)state2)->triggerMode & 3) != 1) return;
            ((InvisibleHitSwitchState*)state)->active = 0;
            GameBit_Set((int)((InvisibleHitSwitchPlacement*)state2)->gameBitId, 0);
        }
        else
        {
            if ((((InvisibleHitSwitchPlacement*)state2)->triggerMode & 3) == 3)
            {
                ((InvisibleHitSwitchState*)state)->activationTimer = lbl_803E3738;
                return;
            }
            ((InvisibleHitSwitchState*)state)->active = 1;
            GameBit_Set((int)((InvisibleHitSwitchPlacement*)state2)->gameBitId, 1);
            if ((((InvisibleHitSwitchPlacement*)state2)->triggerMode & 3) == 2)
            {
                ((InvisibleHitSwitchState*)state)->cooldownTimer =
                    lbl_803E3734 * (lbl_803E373C *
                    (f32)((InvisibleHitSwitchPlacement*)state2)->cooldownFrames);
            }
        }
    }
}

void InvisibleHitSwitch_init(int obj, u8* placement)
{

    InvisibleHitSwitchState* info;

    info = (InvisibleHitSwitchState*)*(int*)&((GameObject*)obj)->extra;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
    if (placement[0x1d] == 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    }
    else
    {
        {
            f32 v = (f32)(u32)placement[0x1d] * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
            ((GameObject*)obj)->anim.rootMotionScale = v * lbl_803E3750;
        }
    }
    ObjHitbox_SetSphereRadius(
        obj,
        (s16)((placement[0x1d] * (int)((GameObject*)obj)->anim.modelInstance->primaryHitboxRadius) / 64));
    info->active = GameBit_Get(((InvisibleHitSwitchPlacement*)placement)->gameBitId);
    switch ((placement[0x23] & 0xe) >> 1)
    {
    case 0:
    default:
        info->hitId = 5;
        break;
    case 1:
        info->hitId = 0x10;
        break;
    case 2:
        info->hitId = 0x15;
        break;
    }
}
