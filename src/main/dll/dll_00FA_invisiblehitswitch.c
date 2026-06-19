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
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    u8 unk1E;
    u8 pad1F[0x20 - 0x1F];
} InvisibleHitSwitchPlacement;

typedef struct InvisibleHitSwitchState
{
    u8 pad0[0x1 - 0x0];
    u8 unk1;
    u8 pad2[0x4 - 0x2];
    f32 unk4;
    f32 unk8;
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
    if (*(u8*)state != 0)
    {
        if (GameBit_Get((int)*(short*)(state2 + 0x18)) == 0)
        {
            *(u8*)state = 0;
        }
    }
    else
    {
        if (GameBit_Get((int)*(short*)(state2 + 0x18)) != 0)
        {
            *(u8*)state = 1;
        }
    }

    if (((InvisibleHitSwitchState*)state)->unk4 > lbl_803E3730)
    {
        ((InvisibleHitSwitchState*)state)->unk4 =
            ((InvisibleHitSwitchState*)state)->unk4 - (f32)(u32)
        framesThisStep;
        if (((InvisibleHitSwitchState*)state)->unk4 <= lbl_803E3730)
        {
            ((InvisibleHitSwitchState*)state)->unk4 = lbl_803E3730;
            GameBit_Set((int)*(short*)(state2 + 0x18), 0);
            return;
        }
        return;
    }

    if (((InvisibleHitSwitchState*)state)->unk8 != *(f32*)&lbl_803E3730)
    {
        ((InvisibleHitSwitchState*)state)->unk8 = ((InvisibleHitSwitchState*)state)->unk8 - timeDelta;
        if (((InvisibleHitSwitchState*)state)->unk8 < lbl_803E3734)
        {
            hitId = ObjHits_GetPriorityHit(obj, 0, 0, 0);
            if ((int)((InvisibleHitSwitchState*)state)->unk1 == hitId)
            {
                ((InvisibleHitSwitchState*)state)->unk8 = lbl_803E3730;
                *(u8*)state = 1;
                GameBit_Set((int)*(short*)(state2 + 0x18), 1);
            }
            else if (((InvisibleHitSwitchState*)state)->unk8 > lbl_803E3730)
            {
            }
            else
            {
                ((InvisibleHitSwitchState*)state)->unk8 = lbl_803E3730;
            }
        }
    }
    else
    {
        hitId = ObjHits_GetPriorityHit(obj, 0, 0, 0);
        if ((int)((InvisibleHitSwitchState*)state)->unk1 != hitId) return;
        if (*(u8*)state != 0)
        {
            if ((((InvisibleHitSwitchPlacement*)state2)->unk1E & 3) != 1) return;
            *(u8*)state = 0;
            GameBit_Set((int)*(short*)(state2 + 0x18), 0);
        }
        else
        {
            if ((((InvisibleHitSwitchPlacement*)state2)->unk1E & 3) == 3)
            {
                ((InvisibleHitSwitchState*)state)->unk8 = lbl_803E3738;
                return;
            }
            *(u8*)state = 1;
            GameBit_Set((int)*(short*)(state2 + 0x18), 1);
            if ((((InvisibleHitSwitchPlacement*)state2)->unk1E & 3) == 2)
            {
                ((InvisibleHitSwitchState*)state)->unk4 =
                    lbl_803E3734 * lbl_803E373C *
                    (f32)((InvisibleHitSwitchPlacement*)state2)->unk1A;
            }
        }
    }
}

void InvisibleHitSwitch_init(int obj, u8* param_2)
{


    u8* info;

    info = (u8*)*(int*)&((GameObject*)obj)->extra;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
    if (param_2[0x1d] == 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    }
    else
    {
        {
            f32 v = (f32)(u32)param_2[0x1d] * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
            ((GameObject*)obj)->anim.rootMotionScale = v * lbl_803E3750;
        }
    }
    ObjHitbox_SetSphereRadius(
        obj,
        (s16)((param_2[0x1d] * (int)((GameObject*)obj)->anim.modelInstance->primaryHitboxRadius) / 64));
    info[0] = GameBit_Get(*(s16*)(param_2 + 0x18));
    switch ((param_2[0x23] & 0xe) >> 1)
    {
    case 0:
    default:
        info[1] = 5;
        break;
    case 1:
        info[1] = 0x10;
        break;
    case 2:
        info[1] = 0x15;
        break;
    }
}
