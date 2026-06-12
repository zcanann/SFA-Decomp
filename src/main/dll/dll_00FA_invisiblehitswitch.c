/* === moved from main/dll/tFrameAnimator.c [8017A350-8017A38C) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/tFrameAnimator.h"
#include "main/game_object.h"
#include "main/objlib.h"



extern void GameBit_Set(int gameBit, int value);



/*
 * --INFO--
 *
 * Function: sidekickball_init
 * EN v1.0 Address: 0x80179EB0
 * EN v1.0 Size: 1220b
 * EN v1.1 Address: 0x80179F40
 * EN v1.1 Size: 1204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


int area_getExtraSize(void);
int area_getObjectTypeId(void);

void area_free(void);

void area_render(void);

void area_hitDetect(void);

void area_update(void);

/* obj->u16_X |= MASK */
void area_init(u16* obj);

void area_release(void);

void area_initialise(void);

/* Trivial 4b 0-arg blr leaves. */





extern u8 framesThisStep;




/* 8b "li r3, N; blr" returners. */



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
#include "main/audio/sfx_ids.h"
#include "main/dll/screenOverlay.h"
#include "main/objanim_internal.h"



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


extern void GameBit_Set(int eventId, int value);

extern f32 timeDelta;
extern f32 lbl_803E3730;
extern f32 lbl_803E3734;
extern f32 lbl_803E3738;
extern f32 lbl_803E373C;


/*
 * --INFO--
 *
 * Function: ProjectileSwitch_render
 * EN v1.0 Address: 0x8017A38C
 * EN v1.0 Size: 140b
 */

/*
 * --INFO--
 *
 * Function: ProjectileSwitch_hitDetect
 * EN v1.0 Address: 0x8017A418
 * EN v1.0 Size: 460b
 */

/*
 * --INFO--
 *
 * Function: ProjectileSwitch_update
 * EN v1.0 Address: 0x8017A5E4
 * EN v1.0 Size: 280b
 */

/*
 * --INFO--
 *
 * Function: ProjectileSwitch_init
 * EN v1.0 Address: 0x8017A6FC
 * EN v1.0 Size: 488b
 */

/* Trivial 4b 0-arg blr leaves. */


/* 8b "li r3, N; blr" returners. */
int InvisibleHitSwitch_getExtraSize(void) { return 0xc; }

/*
 * --INFO--
 *
 * Function: InvisibleHitSwitch_update
 * EN v1.0 Address: 0x8017A8F4
 * EN v1.0 Size: 556b
 */
void InvisibleHitSwitch_update(int obj)
{
    extern uint GameBit_Get(int eventId);
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

    if (lbl_803E3730 < ((InvisibleHitSwitchState*)state)->unk4)
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

    if (((InvisibleHitSwitchState*)state)->unk8 != lbl_803E3730)
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
            else if (lbl_803E3730 < ((InvisibleHitSwitchState*)state)->unk8)
            {
                /* nothing */
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

/* === merged from main/dll/cloudprisoncontrol.c [8017AB20-8017AC2C) (TU re-split, docs/boundary_audit.md) === */
#include "main/game_object.h"


extern f32 lbl_803E3750;

/*
 * --INFO--
 *
 * Function: InvisibleHitSwitch_init
 * EN v1.0 Address: 0x8017AB20
 * EN v1.0 Size: 268b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void InvisibleHitSwitch_init(int obj, u8* param_2)
{
    extern int GameBit_Get(int bitId);
    extern void ObjHitbox_SetSphereRadius(int obj, int radius);
    u8* info;

    info = (u8*)*(int*)&((GameObject*)obj)->extra;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
    if (param_2[0x1d] == 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = *(f32*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 4);
    }
    else
    {
        {
            f32 v = (f32)(u32)param_2[0x1d] * *(f32
            *
            )
            (*(int*)&((GameObject*)obj)->anim.modelInstance + 4);
            ((GameObject*)obj)->anim.rootMotionScale = v * lbl_803E3750;
        }
    }
    ObjHitbox_SetSphereRadius(
        obj,
        (s16)((param_2[0x1d] * (int)*(u8*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x62)) / 64));
    info[0] = (u8)GameBit_Get(*(s16*)(param_2 + 0x18));
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
