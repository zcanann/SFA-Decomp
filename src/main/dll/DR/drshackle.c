#include "main/dll/DR/DRshackle.h"
#include "main/dll/path_control_interface.h"
#include "main/checkpoint_interface.h"

extern f32 sqrtf(f32 x);
extern s16 getAngle(f32 dx, f32 dz);
extern f32 fn_801EA678(int p1, int p2);
extern int objPosToMapBlockIdx(double x, double y, double z);
extern int fn_801EC870(int p1, int p2);
extern void hitDetectFn_800658a4(int p1, f32 x, f32 y, f32 z, f32* out, int flag);

extern f32 timeDelta;

extern f32 lbl_803E5AE8; /* 0.0f  */
extern f32 lbl_803E5AEC; /* 1.0f  */
extern f32 lbl_803E5B08; /* 70.0f */
extern f32 lbl_803E5B10; /* 40.0f */
extern f32 lbl_803E5B68; /* 180.0f */
extern f32 lbl_803E5B6C; /* 56.0f */
extern f32 lbl_803E5B70; /* -1.0f */
extern f32 lbl_803E5B74; /* -0.05f */
extern f32 lbl_803E5B78; /* 2.0f */

#define DRSHACKLE_COLLIDER_OFFSET 0x28
#define DRSHACKLE_COLLIDER_MODE_OFFSET 0x5d
#define DRSHACKLE_MODEL_OFFSET 0x54

#define DRSHACKLE_FLAGS_OFFSET 0x428
#define DRSHACKLE_SWING_ACCEL_OFFSET 0x430
#define DRSHACKLE_FLOOR_ADJUST_FLAG_OFFSET 0x434
#define DRSHACKLE_YAW_OFFSET 0x40c
#define DRSHACKLE_TARGET_YAW_OFFSET 0x40e
#define DRSHACKLE_SWING_COMMAND_OFFSET 0x44c
#define DRSHACKLE_SWING_RETURN_OFFSET 0x458
#define DRSHACKLE_SWING_BLEND_OFFSET 0x45c
#define DRSHACKLE_DISTANCE_FADE_OFFSET 0x3e4
#define DRSHACKLE_LAST_PITCH_OFFSET 0x49c
#define DRSHACKLE_ATTACHMENT_OFFSET 0x178

/* advanceRoute takes a trailing (always-zero) arg not reflected in the shared
 * interface header; cast the slot locally to emit the extra r7=0. */
#define DRSHACKLE_ADVANCE_ROUTE(iface, out, route, dist, mode, flag) \
    ((s32 (*)(u8 *, CheckpointRouteState *, f32, s32, u8, int))(iface)->advanceRoute)( \
        (out), (route), (dist), (mode), (flag), 0)

#define DRSHACKLE_ANGLE_STEP 0xb6
#define DRSHACKLE_SWING_BLEND_LIMIT 0x41
#define DRSHACKLE_SWING_RETURN_LEFT 0x100
#define DRSHACKLE_ANGLE_RETURN_LIMIT 0x2aaa

int drshackle_updateSwingBlend(int obj, int state)
{
    int hitResult;
    int yawDelta;
    f32 fade;

    {
        f32 dx = ((GameObject*)obj)->anim.localPosX;
        f32 dz = ((GameObject*)obj)->anim.localPosZ;
        dx = dx - *(f32*)(state + 0xc);
        dz = dz - *(f32*)(state + 0x14);
        fade = lbl_803E5B68 - sqrtf(dx * dx + dz * dz);
    }

    if (*(f32*)(state + DRSHACKLE_DISTANCE_FADE_OFFSET) != lbl_803E5AE8)
    {
        fade = fade + (((fade - lbl_803E5B10) < lbl_803E5AE8)
                           ? lbl_803E5AE8
                           : (((fade - lbl_803E5B10) > lbl_803E5B08)
                                  ? lbl_803E5B08
                                  : (fade - lbl_803E5B10)));
    }
    if (fade < *(f32*)&lbl_803E5AE8)
    {
        fade = *(f32*)&lbl_803E5AE8;
    }

    hitResult = DRSHACKLE_ADVANCE_ROUTE(
        (*gCheckpointInterface),
        (u8*)state, (CheckpointRouteState*)(state + DRSHACKLE_COLLIDER_OFFSET), fade,
        *(u8*)(state + DRSHACKLE_COLLIDER_MODE_OFFSET), 1);

    (*gCheckpointInterface)
        ->getRouteHeading((GameObject*)obj, (CheckpointRouteState*)(state + DRSHACKLE_COLLIDER_OFFSET));

    (*gCheckpointInterface)->queueRouteRankItem(
        (CheckpointRankItem*)(state + DRSHACKLE_COLLIDER_OFFSET));

    if (hitResult != 0)
    {
        *(f32*)(state + DRSHACKLE_SWING_BLEND_OFFSET) = lbl_803E5AE8;
        return 0;
    }

    yawDelta = (s32)(u16)
    getAngle(((GameObject*)obj)->anim.localPosX - *(f32*)(state + 0xc),
             ((GameObject*)obj)->anim.localPosZ - *(f32*)(state + 0x14)) -
        (s32)(u16) * (s16*)(state + DRSHACKLE_YAW_OFFSET);
    if (0x8000 < yawDelta)
    {
        yawDelta = yawDelta + -0xffff;
    }
    if (yawDelta < -0x8000)
    {
        yawDelta = yawDelta + 0xffff;
    }
    {
        s32 blendStep = yawDelta / DRSHACKLE_ANGLE_STEP;
        if (blendStep < -DRSHACKLE_SWING_BLEND_LIMIT)
        {
            blendStep = -DRSHACKLE_SWING_BLEND_LIMIT;
        }
        else if (blendStep > DRSHACKLE_SWING_BLEND_LIMIT)
        {
            blendStep = DRSHACKLE_SWING_BLEND_LIMIT;
        }
        *(f32*)(state + DRSHACKLE_SWING_BLEND_OFFSET) = (f32)(-blendStep);
    }
    *(s16*)(state + DRSHACKLE_SWING_COMMAND_OFFSET) = 0;
    *(f32*)(state + DRSHACKLE_SWING_BLEND_OFFSET) =
        *(f32*)(state + DRSHACKLE_SWING_BLEND_OFFSET) / lbl_803E5B6C;

    {
        f32 blend = *(f32*)(state + DRSHACKLE_SWING_BLEND_OFFSET);
        *(f32*)(state + DRSHACKLE_SWING_BLEND_OFFSET) =
            (blend < lbl_803E5B70)
                ? lbl_803E5B70
                : ((blend > lbl_803E5AEC) ? lbl_803E5AEC : blend);
    }

    {
        f32 ang = fn_801EA678(obj, state);
        ang = -ang;
        if (*(f32*)(state + DRSHACKLE_LAST_PITCH_OFFSET) < ang ||
            yawDelta > DRSHACKLE_ANGLE_RETURN_LIMIT || yawDelta < -DRSHACKLE_ANGLE_RETURN_LIMIT)
        {
            *(int*)(state + DRSHACKLE_SWING_RETURN_OFFSET) = 0;
        }
        else if (*(f32*)(state + DRSHACKLE_LAST_PITCH_OFFSET) > ang)
        {
            *(int*)(state + DRSHACKLE_SWING_RETURN_OFFSET) = DRSHACKLE_SWING_RETURN_LEFT;
        }
    }
    return 1;
}

int drshackle_updateAttachedPosition(int obj, int state)
{
    ShackleFlags* flags;
    int mapBlockIdx;
    int hitResult;
    s16 angle;
    f32 floorOffset;

    flags = (ShackleFlags*)(state + DRSHACKLE_FLAGS_OFFSET);
    if (flags->active == 0)
    {
        return 0;
    }
    mapBlockIdx = objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                ((GameObject*)obj)->anim.localPosZ);
    if (mapBlockIdx > -1)
    {
        if (flags->positionAnchored == 0)
        {
            {
                f32 zero = lbl_803E5AE8;
                *(f32*)(state + 0x494) = zero;
                *(f32*)(state + 0x498) = zero;
            }
            *(f32*)(state + DRSHACKLE_LAST_PITCH_OFFSET) = -fn_801EA678(obj, state);
            hitResult = DRSHACKLE_ADVANCE_ROUTE(
                (*gCheckpointInterface),
                (u8*)state, (CheckpointRouteState*)(state + DRSHACKLE_COLLIDER_OFFSET),
                -*(f32*)(state + DRSHACKLE_LAST_PITCH_OFFSET) * timeDelta,
                *(u8*)(state + DRSHACKLE_COLLIDER_MODE_OFFSET), 1);
            (*gCheckpointInterface)
                ->getRouteHeading((GameObject*)obj, (CheckpointRouteState*)(state + DRSHACKLE_COLLIDER_OFFSET));
            (*gCheckpointInterface)->queueRouteRankItem(
                (CheckpointRankItem*)(state + DRSHACKLE_COLLIDER_OFFSET));
            if (hitResult != 0)
            {
                return 0;
            }

            fn_801EC870(obj, state);
            angle = (s16)getAngle(((GameObject*)obj)->anim.localPosX - *(f32*)(state + 0xc),
                                  ((GameObject*)obj)->anim.localPosZ - *(f32*)(state + 0x14));
            *(s16*)(obj) = angle;
            *(s16*)(state + DRSHACKLE_TARGET_YAW_OFFSET) = angle;
            *(s16*)(state + DRSHACKLE_YAW_OFFSET) = angle;
            *(f32*)(state + DRSHACKLE_SWING_ACCEL_OFFSET) = lbl_803E5B74;
            ((GameObject*)obj)->anim.localPosX = *(f32*)(state + 0xc);
            ((GameObject*)obj)->anim.localPosY = *(f32*)(state + 0x10);
            ((GameObject*)obj)->anim.localPosZ = *(f32*)(state + 0x14);
            (*gPathControlInterface)->attachObject((void*)obj, (void*)(state + DRSHACKLE_ATTACHMENT_OFFSET));
            *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x10) = ((GameObject*)obj)->anim.localPosX;
            *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x14) = ((GameObject*)obj)->anim.localPosY;
            *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x18) = ((GameObject*)obj)->anim.localPosZ;
            *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x1c) = ((GameObject*)obj)->anim.worldPosX;
            *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x20) = ((GameObject*)obj)->anim.worldPosY;
            *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x24) = ((GameObject*)obj)->anim.worldPosZ;

            if (*(u8*)(state + DRSHACKLE_FLOOR_ADJUST_FLAG_OFFSET) == 0)
            {
                hitDetectFn_800658a4(obj, ((GameObject*)obj)->anim.localPosX,
                                     ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ,
                                     &floorOffset, 0);
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - floorOffset;
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + lbl_803E5B78;
            }
            flags->positionAnchored = 1;
            return 0;
        }
        return drshackle_updateSwingBlend(obj, state) != 0;
    }

    hitResult = DRSHACKLE_ADVANCE_ROUTE(
        (*gCheckpointInterface),
        (u8*)state, (CheckpointRouteState*)(state + DRSHACKLE_COLLIDER_OFFSET),
        timeDelta * fn_801EA678(obj, state), *(u8*)(state + DRSHACKLE_COLLIDER_MODE_OFFSET), 1);
    (*gCheckpointInterface)
        ->getRouteHeading((GameObject*)obj, (CheckpointRouteState*)(state + DRSHACKLE_COLLIDER_OFFSET));
    (*gCheckpointInterface)->queueRouteRankItem(
        (CheckpointRankItem*)(state + DRSHACKLE_COLLIDER_OFFSET));
    if (hitResult != 0)
    {
        return 0;
    }

    angle = (s16)getAngle(((GameObject*)obj)->anim.localPosX - *(f32*)(state + 0xc),
                          ((GameObject*)obj)->anim.localPosZ - *(f32*)(state + 0x14));
    *(s16*)(obj) = angle;
    ((GameObject*)obj)->anim.localPosX = *(f32*)(state + 0xc);
    ((GameObject*)obj)->anim.localPosY = *(f32*)(state + 0x10);
    ((GameObject*)obj)->anim.localPosZ = *(f32*)(state + 0x14);
    (*gPathControlInterface)->attachObject((void*)obj, (void*)(state + DRSHACKLE_ATTACHMENT_OFFSET));
    *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x10) = ((GameObject*)obj)->anim.localPosX;
    *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x14) = ((GameObject*)obj)->anim.localPosY;
    *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x18) = ((GameObject*)obj)->anim.localPosZ;
    *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x1c) = ((GameObject*)obj)->anim.worldPosX;
    *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x20) = ((GameObject*)obj)->anim.worldPosY;
    *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x24) = ((GameObject*)obj)->anim.worldPosZ;
    flags->positionAnchored = 0;
    return 0;
}
