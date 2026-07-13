/*
 * DLL 0xDE - baddieinterestp: an invisible "baddie interest point" trigger
 * object. Most callbacks are empty stubs; BaddieInterestP_render draws the
 * model when visible, and BaddieInterestP_update does the real work: when
 * its placement's gate bits permit (enableGameBit set, doneGameBit clear),
 * it scans ObjGroup 3 for a nearby object matching the placement id
 * (targetIdLo/targetIdHi), then by sun-position mode (modeKind bits 4-5)
 * fires a reaction (fn_801504BC) on staff/baddie seqIds and sets the done
 * bit. The retail TU also owns the gBaddieInterestPObjDescriptor table.
 */

#include "main/dll/xyzanimator.h"
#include "main/dll/dll_00DE_baddieinterestp_api.h"
#include "main/object_render_legacy.h"
#include "main/sky_interface.h"
#include "main/game_object.h"
#include "main/dll/genprops.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/vecmath_distance_api.h"

typedef struct BaddieinterestpPlacement
{
    u8 pad0[0x14 - 0x0];   /* 0x00 */
    s32 linkId;            /* 0x14 id (matched against other placements' linkId) */
    s8 modeKind;           /* 0x18 high nibble = sun mode (bits 4-5), low nibble = reaction kind */
    s8 prob;               /* 0x19 trigger probability (1..100) */
    s16 targetIdLo;        /* 0x1A id low half */
    s16 targetIdHi;        /* 0x1C id high half */
    s16 doneGameBit;       /* 0x1E done-gate gamebit */
    s16 enableGameBit;     /* 0x20 enable-gate gamebit */
    u8 pad22[0x2C - 0x22]; /* 0x22 */
    s16 unk2C;             /* 0x2C layout placeholder; never accessed in this TU */
    u8 pad2E[0x30 - 0x2E]; /* 0x2E */
} BaddieinterestpPlacement;

extern f32 lbl_803E3220;
extern f32 lbl_803E3224;
extern void* ObjGroup_GetObjects();
extern void fn_801504BC(int* obj, int kind);

int BaddieInterestP_getExtraSize(void)
{
    return 0x0;
}

int BaddieInterestP_getObjectTypeId(void)
{
    return 0x0;
}

void BaddieInterestP_free(void)
{
}

void BaddieInterestP_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E3220);
}

void BaddieInterestP_hitDetect(void)
{
}

#pragma opt_loop_invariants off
void BaddieInterestP_update(int* obj)
{
    int* params = *(int**)&((GameObject*)obj)->anim.placementData;

    if (((int)((BaddieinterestpPlacement*)params)->enableGameBit == -1 ||
         mainGetBit((int)((BaddieinterestpPlacement*)params)->enableGameBit) != 0) &&
        ((int)((BaddieinterestpPlacement*)params)->doneGameBit == -1 ||
         mainGetBit((int)((BaddieinterestpPlacement*)params)->doneGameBit) == 0))
    {
        int count;
        int* objs = ObjGroup_GetObjects(3, &count);
        if (count > 0)
        {
            u32 id = (u32)(u16)((BaddieinterestpPlacement*)params)->targetIdHi << 16;
            int* other;
            u16 i;
            u8 found;
            id |= (u16)((BaddieinterestpPlacement*)params)->targetIdLo;
            for (i = 0; i < count; i++)
            {
                int* otherParams;
                other = (int*)objs[i];
                otherParams = *(int**)&((GameObject*)other)->anim.placementData;
                if (otherParams != NULL)
                {
                    found = 0;
                    if (id == *(u32*)&((BaddieinterestpPlacement*)otherParams)->linkId || id == 0)
                    {
                        found = 1;
                    }
                }
                else
                {
                    found = 1;
                }
                if (found != 0)
                {
                    found = 0;
                    if (vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX,
                                              &((GameObject*)other)->anim.worldPosX) < lbl_803E3224)
                    {
                        if (((GameObject*)obj)->unkF4 == 0)
                        {
                            if ((int)randomGetRange(1, 100) <= ((BaddieinterestpPlacement*)params)->prob)
                            {
                                f32 sunTime;
                                int* target;
                                int kind;
                                int b = ((BaddieinterestpPlacement*)params)->modeKind;
                                switch ((b & 0x30) >> 4)
                                {
                                case 0:
                                {
                                    kind = b & 0xf;
                                    target = (int*)objs[i];
                                    if ((int)((BaddieinterestpPlacement*)params)->doneGameBit != -1)
                                    {
                                        mainSetBits((int)((BaddieinterestpPlacement*)params)->doneGameBit, 1);
                                    }
                                    switch (((GameObject*)target)->anim.seqId)
                                    {
                                    case 17:
                                    case 314:
                                    case 1463:
                                    case 1464:
                                    case 1465:
                                    case 1505:
                                        fn_801504BC(target, kind);
                                        break;
                                    }
                                    break;
                                }
                                case 1:
                                    if ((*gSkyInterface)->getSunPosition(&sunTime) == 0)
                                    {
                                        int* target;
                                        int kind;
                                        u8 b2 = (u8)((BaddieinterestpPlacement*)params)->modeKind;
                                        kind = b2 & 0xf;
                                        target = (int*)objs[i];
                                        if ((int)((BaddieinterestpPlacement*)params)->doneGameBit != -1)
                                        {
                                            mainSetBits((int)((BaddieinterestpPlacement*)params)->doneGameBit, 1);
                                        }
                                        switch (((GameObject*)target)->anim.seqId)
                                        {
                                        case 17:
                                        case 314:
                                        case 1463:
                                        case 1464:
                                        case 1465:
                                        case 1505:
                                            fn_801504BC(target, kind);
                                            break;
                                        }
                                    }
                                    break;
                                case 2:
                                    if ((*gSkyInterface)->getSunPosition(&sunTime) != 0)
                                    {
                                        int* target;
                                        int kind;
                                        u8 b2 = (u8)((BaddieinterestpPlacement*)params)->modeKind;
                                        kind = b2 & 0xf;
                                        target = (int*)objs[i];
                                        if ((int)((BaddieinterestpPlacement*)params)->doneGameBit != -1)
                                        {
                                            mainSetBits((int)((BaddieinterestpPlacement*)params)->doneGameBit, 1);
                                        }
                                        switch (((GameObject*)target)->anim.seqId)
                                        {
                                        case 17:
                                        case 314:
                                        case 1463:
                                        case 1464:
                                        case 1465:
                                        case 1505:
                                            fn_801504BC(target, kind);
                                            break;
                                        }
                                    }
                                    break;
                                }
                            }
                            ((GameObject*)obj)->unkF4 = 1;
                        }
                        found = 1;
                    }
                    i = count;
                }
            }
            if (found == 0)
            {
                ((GameObject*)obj)->unkF4 = 0;
            }
        }
    }
}
#pragma opt_loop_invariants reset

void BaddieInterestP_init(void)
{
}

void BaddieInterestP_release(void)
{
}

void BaddieInterestP_initialise(void)
{
}

ObjectDescriptor gBaddieInterestPObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)BaddieInterestP_initialise,
    (ObjectDescriptorCallback)BaddieInterestP_release,
    0,
    (ObjectDescriptorCallback)BaddieInterestP_init,
    (ObjectDescriptorCallback)BaddieInterestP_update,
    (ObjectDescriptorCallback)BaddieInterestP_hitDetect,
    (ObjectDescriptorCallback)BaddieInterestP_render,
    (ObjectDescriptorCallback)BaddieInterestP_free,
    (ObjectDescriptorCallback)BaddieInterestP_getObjectTypeId,
    BaddieInterestP_getExtraSize,
};
