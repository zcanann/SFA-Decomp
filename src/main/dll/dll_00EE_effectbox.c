/*
 * effectbox (DLL 0x00EE) - an oriented box trigger volume placed in a
 * level. Each frame effectbox_update transforms a candidate object's
 * position into the box's local space (yaw/pitch from the placement) and,
 * if it lies inside the box extents, fires an action on that object.
 *
 * The placement's targetMode selects the candidate set: 0 = the player,
 * 1 = Tricky, 2 = every object in object group 5. The action depends on
 * the same mode (the player gets fn_80295918 with actionArg; group members get
 * a vtable call at slot 0x28). A non-negative placement game bit gates the
 * box: it only runs while the bit's value differs from gameBitValue.
 */
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"
#include "main/objlib.h"
#include "main/dll/VF/vf_shared.h"
extern float mathCosf(float x);
extern float mathSinf(float x);
extern void* getTrickyObject(void);
extern void fn_8002B758(void);
extern void fn_8002B860(int obj);
extern void fn_80295918(int obj, int sel, f32 fval);
extern f32 lbl_803E3508;
extern f32 lbl_803E350C;
extern f32 lbl_803E3510;
extern f32 lbl_803E3514;

typedef struct EffectboxPlacement
{
    ObjPlacement base;
    u8 rotYaw;          /* 0x18: yaw in 1/256 turns */
    u8 rotPitch;        /* 0x19: pitch in 1/256 turns */
    u8 extentX;         /* 0x1A */
    u8 extentY;         /* 0x1B */
    u8 extentZ;         /* 0x1C */
    u8 actionArg;           /* 0x1D: action argument */
    u8 pad1E;
    u8 gameBitValue;    /* 0x1F: gate value compared against the game bit */
    s16 gameBitIndex;          /* 0x20: game bit index */
    u8 targetMode;      /* 0x22: EFFECTBOX_TARGET_* candidate set */
    u8 pad23[0x28 - 0x23];
} EffectboxPlacement;

/* EffectboxPlacement.targetMode values */
#define EFFECTBOX_TARGET_PLAYER 0 /* Obj_GetPlayerObject */
#define EFFECTBOX_TARGET_TRICKY 1 /* getTrickyObject */
#define EFFECTBOX_TARGET_GROUP 2  /* every object in object group 5 */

#define EFFECTBOX_OBJFLAG_HIDDEN 0x4000
#define EFFECTBOX_OBJFLAG_HITDETECT_DISABLED 0x2000

int effectbox_getExtraSize(void) { return 0x0; }
int effectbox_getObjectTypeId(void) { return 0x0; }

void effectbox_free(void)
{
    fn_8002B758();
}

void effectbox_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) objRenderFn_8003b8f4(lbl_803E3508);
}

void effectbox_hitDetect(void)
{
}

void effectbox_update(int obj)
{
    int* list;
    int def;
    int single;
    int count;
    int i;
    int other;
    f32 cosY;
    f32 sinY;
    f32 cosX;
    f32 sinX;
    f32 negExtX;
    f32 negExtZ;
    f32 extX;
    f32 extY;
    f32 extZ;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 proj;
    int gb;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    gb = ((GameObject*)obj)->unkF8;
    if ((gb <= -1) || (((EffectboxPlacement*)def)->gameBitValue != GameBit_Get(gb)))
    {
        cosY = mathCosf((lbl_803E350C * (f32) - (((EffectboxPlacement*)def)->rotYaw << 8)) / lbl_803E3510);
        sinY = mathSinf((lbl_803E350C * (f32) - (((EffectboxPlacement*)def)->rotYaw << 8)) / lbl_803E3510);
        cosX = mathCosf((lbl_803E350C * (f32) - (((EffectboxPlacement*)def)->rotPitch << 8)) / lbl_803E3510);
        sinX = mathSinf((lbl_803E350C * (f32) - (((EffectboxPlacement*)def)->rotPitch << 8)) / lbl_803E3510);
        extX = (f32)((EffectboxPlacement*)def)->extentX;
        extY = (f32)(((EffectboxPlacement*)def)->extentY << 1);
        extZ = (f32)((EffectboxPlacement*)def)->extentZ;
        switch (((EffectboxPlacement*)def)->targetMode)
        {
        case EFFECTBOX_TARGET_PLAYER:
            single = (int)Obj_GetPlayerObject();
            if (single == 0u)
            {
                return;
            }
            list = &single;
            count = 1;
            break;
        case EFFECTBOX_TARGET_TRICKY:
            single = (int)getTrickyObject();
            if (single == 0u)
            {
                return;
            }
            list = &single;
            count = 1;
            break;
        case EFFECTBOX_TARGET_GROUP:
            list = (int*)ObjGroup_GetObjects(5, &count);
            if (list == NULL)
            {
                return;
            }
            break;
        }
        i = 0;
        negExtX = -extX;
        negExtZ = -extZ;
        for (; i < count; i++)
        {
            other = *list;
            dx = ((GameObject*)other)->anim.localPosX;
            dy = ((GameObject*)other)->anim.localPosY;
            dz = ((GameObject*)other)->anim.localPosZ;
            dx = dx - ((GameObject*)obj)->anim.localPosX;
            dy = dy - ((GameObject*)obj)->anim.localPosY;
            dz = dz - ((GameObject*)obj)->anim.localPosZ;
            proj = dx * cosY + dz * sinY;
            if ((proj > negExtX) && (proj < extX))
            {
                proj = (-dx) * sinY + dz * cosY;
                proj = (-dy) * sinX + proj * cosX;
                if ((proj > negExtZ) && (proj < extZ))
                {
                    proj = dy * cosX + proj * sinX;
                    if ((proj >= lbl_803E3514) && (proj < extY))
                    {
                        switch (((EffectboxPlacement*)def)->targetMode)
                        {
                        case EFFECTBOX_TARGET_TRICKY:
                            break;
                        case EFFECTBOX_TARGET_PLAYER:
                            fn_80295918(other, 1, (f32)((EffectboxPlacement*)def)->actionArg);
                            break;
                        case EFFECTBOX_TARGET_GROUP:
                            (*(VtableFn*)(*(int*)(*(int*)&((GameObject*)other)->anim.dll) + 0x28))(other, ((EffectboxPlacement*)def)->actionArg);
                            break;
                        }
                    }
                }
            }
            list++;
        }
    }
}

void effectbox_init(int obj, EffectboxPlacement* def)
{
    s16 gameBit;
    u32 flags;
    if (((GameObject*)obj)->unkF4 == 0)
    {
        fn_8002B860(obj);
    }
    ((GameObject*)obj)->unkF4 = 1;
    gameBit = def->gameBitIndex;
    if (gameBit > -1)
    {
        ((GameObject*)obj)->unkF8 = gameBit;
    }
    else
    {
        ((GameObject*)obj)->unkF8 = -1;
    }
    flags = (u32)((GameObject*)obj)->objectFlags | (EFFECTBOX_OBJFLAG_HIDDEN | EFFECTBOX_OBJFLAG_HITDETECT_DISABLED);
    ((GameObject*)obj)->objectFlags = flags;
}

/* gEffectBoxObjDescriptor (.data 0x80320D10) lives in a separate DLL
 * entry TU; this TU owns only the .text callbacks. */
void effectbox_release(void)
{
}

void effectbox_initialise(void)
{
}

ObjectDescriptor gEffectBoxObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)effectbox_initialise,
    (ObjectDescriptorCallback)effectbox_release,
    0,
    (ObjectDescriptorCallback)effectbox_init,
    (ObjectDescriptorCallback)effectbox_update,
    (ObjectDescriptorCallback)effectbox_hitDetect,
    (ObjectDescriptorCallback)effectbox_render,
    (ObjectDescriptorCallback)effectbox_free,
    (ObjectDescriptorCallback)effectbox_getObjectTypeId,
    effectbox_getExtraSize,
};

/* .sdata2 constant pool (shared floats/doubles referenced via extern by sibling objects) */
const f32 lbl_803E3528 = 0.0f;
const f32 lbl_803E352C = -175.0f;
const f64 lbl_803E3530 = 188.0;
const f32 lbl_803E3538 = 3.6132812f;
const f32 lbl_803E353C = 0.0f;
const f32 lbl_803E3540 = 1e+04f;
const f32 lbl_803E3544 = 0.001f;
const f32 lbl_803E3548 = 0.02f;
const f32 lbl_803E354C = 3e+02f;
const f32 lbl_803E3550 = 1.5e+02f;
const f32 lbl_803E3554 = -1.0f;
const f32 lbl_803E3558 = 1e+01f;
const f32 lbl_803E355C = 3e+01f;
const f32 lbl_803E3560 = 4e+01f;
const f32 lbl_803E3564 = 0.01f;
const f32 lbl_803E3568 = 225.0f;
const f32 lbl_803E356C = 255.0f;
const f32 lbl_803E3570 = 0.25f;
const f32 lbl_803E3574 = 0.0f;
const f32 lbl_803E3578 = 176.0f;
const f32 lbl_803E357C = -0.0f;
const f32 lbl_803E3580 = 1.2f;
const f32 lbl_803E3584 = 0.6f;
const f32 lbl_803E3588 = 1.0f;
const f32 lbl_803E358C = 0.5f;
const f32 gPushablePi = 3.1415927f;
const f32 gPushableYawHalfCircle = 32768.0f;
const f32 lbl_803E3598 = 4.0f;
const f32 lbl_803E359C = 15.0f;
const f32 lbl_803E35A0 = 8.0f;
const f32 lbl_803E35A4 = 9.5f;
const f32 lbl_803E35A8 = 0.985f;
const f32 lbl_803E35AC = 0.94f;
const f32 lbl_803E35B0 = 0.05f;
const f32 lbl_803E35B4 = -0.05f;
const f32 lbl_803E35B8 = 0.1f;
const f32 lbl_803E35BC = 2e+02f;
const f32 lbl_803E35C0 = 5e+01f;
const f32 lbl_803E35C4 = 0.707f;
const f32 lbl_803E35C8 = 2e+01f;
const f32 gPushableU16ScaleDenom = 65535.0f;
const f64 lbl_803E35D0 = 4503599627370496.0;
const f32 lbl_803E35D8 = 1e+02f;
const f32 lbl_803E35DC = 0.0f;
const f32 lbl_803E35E0 = 176.0f;
const f32 lbl_803E35E4 = -0.0f;
const f32 lbl_803E35E8 = 1.0f;
const f32 lbl_803E35EC = 48.0f;
const f32 lbl_803E35F0 = 1e+01f;
const f32 lbl_803E35F4 = 2e+01f;
const f64 lbl_803E35F8 = 4503601774854144.0;
const f32 lbl_803E3600 = 1.0f;
const f32 lbl_803E3604 = 0.0f;
const f32 lbl_803E3608 = 24.0f;
const f32 lbl_803E360C = -3.0f;
const f32 lbl_803E3610 = 176.0f;
const f32 lbl_803E3614 = -0.0f;
const f32 lbl_803E3618 = 0.0f;
const f32 lbl_803E361C = -1.5f;
const f32 lbl_803E3620 = 1.0f;
const f32 gFlameBlastReachScale = 0.4f;
const f32 lbl_803E3628 = 0.2f;
const f32 gFlameBlastRenderScaleRate = 0.033333335f;
const f32 gFlameBlastFireInterval = 24.0f;
const f32 gFlameBlastHitArmTime = 6.0f;
const f32 gFlameBlastInitTimerScale = 3.4285715f;
const f32 lbl_803E363C = 0.0f;
const f64 lbl_803E3640 = 4503601774854144.0;
const f32 lbl_803E3648 = 0.0f;
const f32 gDoorF4Pi = 3.1415927f;
const f32 gDoorF4BinaryAngleScale = 32768.0f;
const f32 lbl_803E3654 = 2e+02f;
const f32 lbl_803E3658 = -3e+01f;
const f32 lbl_803E365C = 3e+01f;
const f32 lbl_803E3660 = 3.2e+02f;
const f32 lbl_803E3664 = 1.6e+02f;
const f32 lbl_803E3668 = -2e+02f;
const f32 lbl_803E366C = 6e+01f;
const f32 lbl_803E3670 = -6e+01f;
const f32 lbl_803E3674 = 1e+03f;
const f32 lbl_803E3678 = 176.0f;
const f32 lbl_803E367C = -0.0f;
const f32 lbl_803E3680 = 1.0f;
const f32 lbl_803E3684 = 1e+02f;
const f32 lbl_803E3688 = 0.75f;
const f32 lbl_803E368C = 2.2f;
const f32 lbl_803E3690 = 0.25f;
const f32 lbl_803E3694 = -2.2f;
const f32 lbl_803E3698 = -0.25f;
const f32 lbl_803E369C = 0.0f;
const f32 lbl_803E36A0 = 1.0f;
const f32 gSidekickBallFadeDuration = 6e+01f;
const f32 gSidekickBallActiveTimeout = 3e+02f;
const f32 gSidekickBallMaxAlpha = 255.0f;
const f32 gSidekickBallRestitution = 0.7f;
const f32 lbl_803E36B4 = 0.01f;
const f32 gSidekickBallFloorDamping = 0.95f;
const f32 lbl_803E36BC = 0.025f;
const f32 lbl_803E36C0 = 0.2f;
const f32 lbl_803E36C4 = -0.2f;
const f32 gSidekickBallGravity = 0.05f;
const f32 lbl_803E36CC = 0.5f;
const f32 lbl_803E36D0 = 2.0f;
const f32 lbl_803E36D4 = 0.3f;
const f64 lbl_803E36D8 = 4503601774854144.0;
const f32 lbl_803E36E0 = 3e+01f;
const f32 lbl_803E36E4 = 3.1415927f;
const f32 lbl_803E36E8 = 32768.0f;
const f32 lbl_803E36EC = 0.0f;
const f32 lbl_803E36F0 = 176.0f;
const f32 lbl_803E36F4 = 0.0f;
const f64 lbl_803E36F8 = 4503601774854144.0;
const f32 lbl_803E3700 = 1.0f;
const f32 lbl_803E3704 = 6e+01f;
const f32 lbl_803E3708 = 0.1f;
const f32 lbl_803E370C = 0.0f;
const f32 lbl_803E3710 = 176.0f;
const f32 lbl_803E3714 = -0.0f;
const f32 lbl_803E3718 = 0.0f;
const f32 lbl_803E371C = 0.0f;
const f32 lbl_803E3720 = 176.0f;
const f32 lbl_803E3724 = 0.0f;
const f32 lbl_803E3728[2] = { 0.015625f, 0.0f };
const f32 lbl_803E3730 = 0.0f;
const f32 lbl_803E3734 = 6e+01f;
const f32 lbl_803E3738 = 1.2e+02f;
const f32 lbl_803E373C = 0.1f;
const f32 lbl_803E3740 = 176.0f;
const f32 lbl_803E3744 = 0.0f;
const f32 lbl_803E3748 = 176.0f;
const f32 lbl_803E374C = -0.0f;
const f32 lbl_803E3750 = 0.015625f;
const f32 lbl_803E3754 = 0.0f;
const f32 lbl_803E3758 = 4e+01f;
const f32 lbl_803E375C = 2e+02f;
const f32 lbl_803E3760 = 0.0f;
const f32 lbl_803E3764 = 4.5f;
const f32 lbl_803E3768 = 1.5f;
const f32 lbl_803E376C = 0.0f;
const f32 lbl_803E3770 = 176.0f;
const f32 lbl_803E3774 = 0.0f;
const f32 lbl_803E3778 = 0.125f;
const f32 lbl_803E377C = 0.0f;
const f32 lbl_803E3780 = 1.0f;
const f32 gDoorRootMotionScaleFactor = 0.015625f;
const f32 lbl_803E3788 = 0.0f;
const f32 lbl_803E378C = 0.0f;
const f32 lbl_803E3790 = 176.0f;
const f32 lbl_803E3794 = 0.0f;
const f32 lbl_803E3798 = 1.0f;
const f32 lbl_803E379C = 0.0f;
const f32 lbl_803E37A0 = 1.0f;
const f32 lbl_803E37A4 = 0.0f;
const f32 lbl_803E37A8 = 1.0f;
const f32 lbl_803E37AC = 0.0f;
const f32 lbl_803E37B0[2] = { 1.0f, 0.0f };
const f32 lbl_803E37B8 = 1.0f;
const f32 lbl_803E37BC = 1e+04f;
const f32 lbl_803E37C0 = 35.0f;
const f32 lbl_803E37C4 = 6e+01f;
const f32 lbl_803E37C8 = 1.0f;
const f32 lbl_803E37CC = 0.25f;
const f32 lbl_803E37D0 = 0.75f;
const f32 lbl_803E37D4 = 0.0f;
const f32 lbl_803E37D8 = 4.0f;
const f32 lbl_803E37DC = 2.0f;
const f32 lbl_803E37E0 = 0.0001f;
const f32 lbl_803E37E4 = -0.0f;
const f32 lbl_803E37E8 = 0.5f;
const f32 gAppleOnTreePickupXZRange = 15.0f;
const f32 gAppleOnTreePickupRange = 3e+01f;
const f32 lbl_803E37F4 = 0.1f;
const f32 lbl_803E37F8 = 0.66667f;
const f32 lbl_803E37FC = 0.0401f;
const f32 lbl_803E3800 = -0.02f;
const f32 lbl_803E3804 = -0.006f;
const f32 lbl_803E3808 = 0.006f;
const f32 lbl_803E380C = 64.0f;
const f32 lbl_803E3810 = 1.8e+02f;
const f32 lbl_803E3814 = 6e+01f;
const f32 lbl_803E3818 = 255.0f;
const f32 lbl_803E381C = 0.0f;
const f64 lbl_803E3820 = 4503601774854144.0;
const f32 lbl_803E3828 = 1e+02f;
const f32 lbl_803E382C = -0.04f;
const f32 lbl_803E3830 = 0.00390625f;
const f32 lbl_803E3834 = 0.001f;
const f32 lbl_803E3838 = 61.0f;
const f32 lbl_803E383C = 0.0f;
const f32 lbl_803E3840 = 176.0f;
const f32 lbl_803E3844 = 0.0f;
const f32 lbl_803E3848 = 1.0f;
const f32 lbl_803E384C = 1e+02f;
const f32 lbl_803E3850 = 1.0f;
const f32 lbl_803E3854 = 1e+02f;
const f32 lbl_803E3858 = 1.0f;
const f32 lbl_803E385C = 0.0f;
const f32 lbl_803E3860 = 176.0f;
const f32 lbl_803E3864 = -0.0f;
const f32 lbl_803E3868 = 176.0f;
const f32 lbl_803E386C = 0.0f;
const f32 lbl_803E3870 = 0.8f;
const f32 lbl_803E3874 = 1e+02f;
const f32 lbl_803E3878 = 3.1415927f;
const f32 lbl_803E387C = 32768.0f;
const f32 lbl_803E3880 = 0.004f;
const f32 lbl_803E3884 = 0.03f;
const f32 lbl_803E3888 = 0.014f;
const f32 lbl_803E388C = 0.005f;
const f32 lbl_803E3890 = 0.01f;
const f32 lbl_803E3894 = 5e+01f;
const f32 lbl_803E3898 = 7e+01f;
const f32 lbl_803E389C = 0.0f;
const f32 lbl_803E38A0 = 19.0f;
const f32 lbl_803E38A4 = 0.0f;
const f32 lbl_803E38A8 = 1e+02f;
const f32 lbl_803E38AC = 0.0f;
const f32 lbl_803E38B0 = 1.0f;
const f32 gDusterObjHitDetectRadius = 6.0f;
const f32 gDusterObjGravityVelYThreshold = -6.0f;
const f32 gDusterObjGravityAccel = -0.05f;
const f32 gDusterObjFloorSearchMaxDelta = 1e+05f;
const f32 lbl_803E38C4 = 0.0f;
const f32 gDusterObjLaunchVelocityX = 0.2f;
const f32 gDusterObjDriftSpinRate = 3e+03f;
const f32 gDusterObjPickupRangeY = 3e+01f;
const f32 gDusterObjPickupRangeXZ = 2e+01f;
const f32 lbl_803E38D8 = 176.0f;
const f32 lbl_803E38DC = -0.0f;
const f32 gDusterObjMoveStepScale = 0.02f;
const f32 lbl_803E38E4 = 0.0f;
const u32 gCurveFishCurveQueryKey = 0x00000023;
const f32 lbl_803E38EC = 6e+01f;
const f32 lbl_803E38F0 = 0.0f;
const f32 lbl_803E38F4 = 255.0f;
const f32 lbl_803E38F8 = 2.0f;
const f32 lbl_803E38FC = 1e+03f;
const f32 lbl_803E3900 = 0.25f;
const f32 lbl_803E3904 = 1.2e+02f;
const f32 lbl_803E3908 = 0.0075f;
const f32 lbl_803E390C = 3.0f;
const f32 lbl_803E3910 = 2.4e+02f;
const f32 lbl_803E3914 = 0.015f;
const f32 lbl_803E3918 = 176.0f;
const f32 lbl_803E391C = 0.0f;
const f32 lbl_803E3920 = 176.0f;
const f32 lbl_803E3924 = -0.0f;
const f32 lbl_803E3928 = 1e+02f;
const f32 lbl_803E392C = 0.0f;
const f32 lbl_803E3930 = 1e+02f;
const f32 lbl_803E3934 = 0.014f;
const f32 lbl_803E3938 = 0.0f;
const f32 lbl_803E393C = 0.25f;
const f32 lbl_803E3940 = 5e+01f;
const f32 lbl_803E3944 = 75.0f;
const f32 lbl_803E3948 = 3.0f;
const f32 lbl_803E394C = 4.0f;
const f32 lbl_803E3950 = 1.0f;
const f32 lbl_803E3954 = 0.01f;
const f32 lbl_803E3958 = 2.2f;
const f32 lbl_803E395C = 15.0f;
const f32 lbl_803E3960 = 5.0f;
const f32 lbl_803E3964 = 2.0f;
const f32 lbl_803E3968 = 176.0f;
const f32 lbl_803E396C = -0.0f;
const f32 lbl_803E3970 = 0.1f;
const f32 lbl_803E3974 = -2.2f;
const f32 lbl_803E3978 = 8.0f;
const f32 lbl_803E397C = 0.75f;
const f32 lbl_803E3980 = -0.75f;
const f32 lbl_803E3984 = 1.2f;
const f32 lbl_803E3988 = 0.35f;
const f32 lbl_803E398C = -1.2f;
const f32 lbl_803E3990 = -0.35f;
const f32 lbl_803E3994 = -1e+01f;
const f32 lbl_803E3998[2] = { -0.12f, 0.0f };
const f64 lbl_803E39A0 = 4503599627370496.0;
const f32 lbl_803E39A8 = 2.0f;
const f32 lbl_803E39AC = 1.0f;
const f32 lbl_803E39B0 = 176.0f;
const f32 lbl_803E39B4 = 0.0f;
const f32 lbl_803E39B8 = 0.0f;
const f32 lbl_803E39BC = 2e+02f;
const f32 lbl_803E39C0 = 5.0f;
const f32 lbl_803E39C4 = 6e+01f;
const f32 lbl_803E39C8 = 176.0f;
const f32 lbl_803E39CC = -0.0f;
const f32 lbl_803E39D0 = 1e+02f;
const f32 lbl_803E39D4 = 0.01f;
const f32 lbl_803E39D8 = 2.2f;
const f32 lbl_803E39DC = 8.0f;
const f32 lbl_803E39E0 = -0.5f;
const f32 lbl_803E39E4 = 0.014f;
const f32 lbl_803E39E8 = 1.5e+03f;
const f32 lbl_803E39EC = 0.0f;
const u32 gScarabMoneyValues = 0x01050A32;
const f32 lbl_803E39F4 = 8.0f;
const f32 lbl_803E39F8 = 0.0f;
const f32 lbl_803E39FC = 2.0f;
const f32 lbl_803E3A00 = 1.0f;
const f32 lbl_803E3A04 = 2.5f;
const f32 lbl_803E3A08 = -15.0f;
const f32 lbl_803E3A0C = -0.06f;
const f32 lbl_803E3A10 = 0.15f;
const f32 lbl_803E3A14 = 0.65f;
const f32 lbl_803E3A18 = 1.2f;
const f32 lbl_803E3A1C = 0.45f;
const f32 lbl_803E3A20 = 0.2f;
const f32 lbl_803E3A24 = 2.2f;
const f32 lbl_803E3A28 = 1e+04f;
const f32 lbl_803E3A2C = 32768.0f;
const f32 lbl_803E3A30 = 3e+02f;
const f32 lbl_803E3A34 = -1.0f;
const f32 lbl_803E3A38 = 25.0f;
const f32 lbl_803E3A3C = 2e+01f;
const f32 lbl_803E3A40 = 26.0f;
const f32 lbl_803E3A44 = 0.0f;
const f32 lbl_803E3A48 = 176.0f;
const f32 lbl_803E3A4C = -0.0f;
const f64 lbl_803E3A50 = 4503599627370496.0;
const f32 lbl_803E3A58 = 0.0f;
const f32 lbl_803E3A5C = 1.0f;
const f32 lbl_803E3A60 = 2.2f;
const f32 lbl_803E3A64 = 0.75f;
const f32 lbl_803E3A68 = -2.2f;
const f32 lbl_803E3A6C = -0.75f;
const f32 lbl_803E3A70 = -1e+01f;
const f32 gWindLift107LaunchGravity = -0.12f;
const f32 lbl_803E3A78 = 176.0f;
const f32 lbl_803E3A7C = -0.0f;
const f32 gWindLift107RadiusScale = 1e+01f;
const f32 gWindLift107DefaultRadius = 5e+01f;
const f32 lbl_803E3A88 = 1.0f;
const f32 lbl_803E3A8C = 3.1499999f;
const f32 lbl_803E3A90 = 0.5f;
const f32 lbl_803E3A94 = 0.0f;
const f32 lbl_803E3A98 = 8e+01f;
const f32 lbl_803E3A9C = 1e+02f;
const f32 lbl_803E3AA0 = 1.0f;
const f32 lbl_803E3AA4 = 4e+01f;
const f32 lbl_803E3AA8 = 34.0f;
const f32 lbl_803E3AAC = 0.0f;
const f64 lbl_803E3AB0 = 4503601774854144.0;
const f32 lbl_803E3AB8 = 0.0f;
const f32 lbl_803E3ABC = 21.0f;
const f32 lbl_803E3AC0 = 0.0001f;
const f32 lbl_803E3AC4 = 0.0015f;
const f32 lbl_803E3AC8 = 2.5f;
const f32 gLanternFireflyPi = 3.1415927f;
const f32 lbl_803E3AD0 = 32768.0f;
const f32 lbl_803E3AD4 = 3e+01f;
const f32 lbl_803E3AD8 = 0.08f;
const f32 lbl_803E3ADC = 0.0275f;
const f32 lbl_803E3AE0[2] = { 5.0f, 0.0f };
const f32 lbl_803E3AE8 = 2.0f;
const f32 lbl_803E3AEC = 5.0f;
const f32 lbl_803E3AF0[2] = { 1.0f, 0.0f };
const f32 lbl_803E3AF8 = 1.0f;
const f32 gFlammableVineBurnDuration = 2.4e+02f;
const f32 lbl_803E3B00 = 0.0f;
const f32 lbl_803E3B04 = 1.2e+02f;
const f32 lbl_803E3B08 = 1.8e+02f;
const f32 lbl_803E3B0C = 6e+01f;
const f32 lbl_803E3B10 = 1.5e+02f;
const f32 gFlammableVineMaxAlpha = 255.0f;
const f32 lbl_803E3B18 = 3e+01f;
const f32 lbl_803E3B1C = 0.65f;
const f32 lbl_803E3B20 = 5.0f;
const f32 gFlammableVineScaleParamNormalize = 32767.0f;
const f32 gFlammableVineMinScale = 0.05f;
const f32 lbl_803E3B2C = 14.0f;
const f32 lbl_803E3B30 = 25.0f;
const f32 lbl_803E3B34 = 0.001f;
const f64 lbl_803E3B38 = 4503601774854144.0;
const f32 lbl_803E3B40 = 1.0f;
const f32 lbl_803E3B44 = 0.0f;
const f32 lbl_803E3B48 = 3e+02f;
const f32 lbl_803E3B4C = 0.0f;
const f32 lbl_803E3B50 = 0.9f;
const f32 lbl_803E3B54 = 0.3f;
const f32 lbl_803E3B58 = 0.0f;
const f32 lbl_803E3B5C = 0.01f;
const f32 lbl_803E3B60 = 176.0f;
const f32 lbl_803E3B64 = -0.0f;
const f32 lbl_803E3B68 = -3e+01f;
const f32 lbl_803E3B6C = 2.4e+02f;
const f32 lbl_803E3B70[2] = { 1.0f, 0.0f };
const f32 lbl_803E3B78 = 1.0f;
const f32 lbl_803E3B7C = 0.0f;
const f32 lbl_803E3B80 = 176.0f;
const f32 lbl_803E3B84 = -0.0f;
const f32 lbl_803E3B88 = 255.0f;
const f32 lbl_803E3B8C = 0.0f;
const f32 lbl_803E3B90 = 176.0f;
const f32 lbl_803E3B94 = 0.0f;
const f32 lbl_803E3B98 = 0.0f;
const f32 lbl_803E3B9C = 0.7f;
const f32 lbl_803E3BA0 = 2e+01f;
const f32 lbl_803E3BA4 = 1.0f;
const f32 lbl_803E3BA8 = 0.2f;
const f32 lbl_803E3BAC = 0.4f;
const f32 lbl_803E3BB0 = 0.6f;
const f32 lbl_803E3BB4 = 0.0f;
const f32 lbl_803E3BB8 = 2.0f;
const f32 lbl_803E3BBC = 1.0f;
const f32 lbl_803E3BC0 = 1e+02f;
const f32 lbl_803E3BC4 = 0.01f;
const f32 lbl_803E3BC8 = 4.0f;
const f32 lbl_803E3BCC = 2048.0f;
const f64 lbl_803E3BD0 = 4503601774854144.0;
const f32 lbl_803E3BD8 = 6e+01f;
const f32 lbl_803E3BDC = 0.0f;
const f32 lbl_803E3BE0 = 2.2f;
const f32 lbl_803E3BE4 = 0.0f;
const f32 lbl_803E3BE8 = 176.0f;
const f32 lbl_803E3BEC = 0.0f;
const f32 lbl_803E3BF0 = 2e+01f;
const f32 gStaffActivatedPi = 3.1415927f;
const f32 gStaffActivatedBinAngleScale = 32768.0f;
const f32 lbl_803E3BFC = 18.0f;
const f32 lbl_803E3C00 = 2.8f;
const f32 lbl_803E3C04 = 1.7f;
const f32 lbl_803E3C08 = 1.25f;
const f32 lbl_803E3C0C = 0.75f;
const f32 gStaffActivatedMinRootMotionScale = 0.1f;
const f32 lbl_803E3C14 = 0.5f;
const f32 lbl_803E3C18 = 1e+01f;
const f32 lbl_803E3C1C = 0.0f;
const f32 lbl_803E3C20 = 1.0f;
const f32 lbl_803E3C24 = 0.6f;
const f32 lbl_803E3C28 = 2e+01f;
const f32 lbl_803E3C2C = 0.99f;
const f32 lbl_803E3C30 = 225.0f;
const f32 lbl_803E3C34 = 1.44e+04f;
const f32 lbl_803E3C38 = 0.0f;
const f32 lbl_803E3C3C = 3.6e+03f;
const f32 lbl_803E3C40 = 8.1e+03f;
const f32 lbl_803E3C44 = 3.0f;
const f32 lbl_803E3C48 = 3e+02f;
const f32 gMagicCaveTopFadeMax = 1e+02f;
const f32 gMagicCaveTopAlphaMax = 255.0f;
const f32 lbl_803E3C54 = 4e+01f;
const f32 lbl_803E3C58 = 0.5f;
const f32 lbl_803E3C5C = 18.0f;
const f32 lbl_803E3C60 = 8.0f;
const f32 lbl_803E3C64 = 8e+01f;
const f32 lbl_803E3C68 = 5.0f;
const f32 lbl_803E3C6C = 1e+01f;
const f32 lbl_803E3C70 = 176.0f;
const f32 lbl_803E3C74 = -0.0f;
const f32 lbl_803E3C78 = 176.0f;
const f32 lbl_803E3C7C = -0.0f;
const f32 lbl_803E3C80 = 6e+02f;
const f32 lbl_803E3C84 = 0.0f;
const f32 lbl_803E3C88 = 6e+02f;
const f32 lbl_803E3C8C = 0.0f;
const f32 lbl_803E3C90 = 35.0f;
const f32 lbl_803E3C94 = 5.0f;
const f32 lbl_803E3C98 = 1e+03f;
const f32 lbl_803E3C9C = 0.1f;
const f32 lbl_803E3CA0 = 0.0005f;
const f32 lbl_803E3CA4 = 3e+01f;
const f32 gDeathGasTimerFull = 6e+03f;
const f32 lbl_803E3CAC = 1e+01f;
const f32 lbl_803E3CB0 = 0.0f;
const f32 lbl_803E3CB4 = 1.2e+02f;
const f32 lbl_803E3CB8 = 176.0f;
const f32 lbl_803E3CBC = 0.0f;
const f32 gDeathGasDefaultRadius = 1e+04f;
const f32 lbl_803E3CC4 = 0.0f;
const f32 lbl_803E3CC8 = 4.0f;
const f32 lbl_803E3CCC = 1.0f;
const f32 lbl_803E3CD0 = 3.5f;
const f32 lbl_803E3CD4 = 4.5f;
const f32 lbl_803E3CD8 = 0.5f;
const f32 gFuelCellMaxLinkDistSq = 1e+04f;
const f32 lbl_803E3CE0 = 1e+02f;
const f32 lbl_803E3CE4 = 0.1f;
const f32 lbl_803E3CE8 = 0.07f;
const f32 lbl_803E3CEC = 0.0017f;
const f32 lbl_803E3CF0 = 0.003f;
const f32 lbl_803E3CF4 = 0.2f;
const f32 lbl_803E3CF8[2] = { 0.0f, 0.0f };
const f64 lbl_803E3D00 = 4503601774854144.0;
const f32 lbl_803E3D08 = -5.0f;
const f32 lbl_803E3D0C = 4e+01f;
const f32 lbl_803E3D10 = 81.0f;
const f32 lbl_803E3D14 = 0.0f;
const f32 lbl_803E3D18 = 5e+01f;
const f32 lbl_803E3D1C = 0.0f;
const f32 lbl_803E3D20 = 0.005f;
const f32 lbl_803E3D24 = 0.5f;
const f32 lbl_803E3D28 = 1.0f;
const f32 lbl_803E3D2C = 4e+01f;
const f32 gDeathSeqCameraYawAngle = -0.7853982f;
const f32 gDeathSeqCameraPitchAngle = 0.3926991f;
const f32 lbl_803E3D38 = 1e+01f;
const f32 gDeathSeqPi = 3.1415927f;
const f32 gDeathSeqAngleHalfCircle = 32768.0f;
const f32 gDeathSeqCameraFovY = 6e+01f;
const f32 lbl_803E3D48 = 0.01f;
const f32 lbl_803E3D4C = 0.0f;
const f32 lbl_803E3D50 = 176.0f;
const f32 lbl_803E3D54 = -0.0f;
const f32 lbl_803E3D58 = 2.1e+02f;
const f32 lbl_803E3D5C = 0.0f;
const f32 lbl_803E3D60 = 1.0f;
const f32 lbl_803E3D64 = 1e+01f;
const f32 lbl_803E3D68 = 0.015625f;
const f32 lbl_803E3D6C = 0.0f;
const f64 lbl_803E3D70 = 4503601774854144.0;
const f32 lbl_803E3D78 = 1.0f;
const f32 lbl_803E3D7C = 0.0f;
const f32 lbl_803E3D80 = 1e+01f;
const f32 lbl_803E3D84 = 1.4f;
const f32 gCampfireSizeToScale = 0.01f;
const f32 lbl_803E3D8C = 2e+01f;
const f32 lbl_803E3D90 = 3e+01f;
const f32 lbl_803E3D94 = 12.0f;
const f32 lbl_803E3D98[2] = { 4e+01f, 0.0f };
const f32 lbl_803E3DA0 = 176.0f;
const f32 lbl_803E3DA4 = 0.0f;
const f32 lbl_803E3DA8 = 176.0f;
const f32 lbl_803E3DAC = -0.0f;
const f32 lbl_803E3DB0 = 1.0f;
const f32 lbl_803E3DB4 = 1e+04f;
const f32 lbl_803E3DB8 = 176.0f;
const f32 lbl_803E3DBC = 0.0f;
const f32 lbl_803E3DC0 = 1e+01f;
const f32 lbl_803E3DC4 = 0.015625f;
const f32 lbl_803E3DC8[2] = { 0.00390625f, 0.0f };
const f32 lbl_803E3DD0 = 176.0f;
const f32 lbl_803E3DD4 = -0.0f;
const f32 lbl_803E3DD8 = 1.0f;
const f32 lbl_803E3DDC = 0.0f;
const f64 lbl_803E3DE0 = 2.0;
const f32 lbl_803E3DE8 = 4e+01f;
const f32 lbl_803E3DEC = 0.5f;
const f32 lbl_803E3DF0 = 4e+03f;
const f32 lbl_803E3DF4 = 1e+03f;
const f32 lbl_803E3DF8 = 0.002f;
const f32 lbl_803E3DFC = 3e+01f;
const f32 lbl_803E3E00 = 1e+02f;
const f32 lbl_803E3E04 = 3.0f;
const f32 lbl_803E3E08 = 1.8e+02f;
const f32 lbl_803E3E0C = -1.8e+02f;
const f32 lbl_803E3E10 = 9e+01f;
const f32 lbl_803E3E14 = -9e+01f;
const f64 lbl_803E3E18 = 1.5;
const f32 lbl_803E3E20[2] = { 75.0f, 0.0f };
