/*
 * drshackle swing/attachment math (part of the DR shackle object; the
 * object's lifecycle callbacks live in dll_026E_drshackle.c).
 *
 * drshackle_updateAttachedPosition rides the shackle along its checkpoint
 * route while it tracks the player: on first contact it anchors to the
 * route (snapping yaw, seeding swing accel and floor offset), thereafter
 * it advances the route and blends the swing each frame.
 * drshackle_updateSwingBlend computes the per-frame swing-blend factor
 * from the yaw delta between the object and its anchor, clamps it, and
 * decides the return direction.
 *
 * `state` is a raw byte base; field offsets are spelled via the
 * DRSHACKLE_*_OFFSET macros. Several `lbl_803E5Bxx` are plain float
 * constants (see the inline value comments).
 */
#include "main/dll/DR/DRshackle.h"
#include "main/dll/path_control_interface.h"
#include "main/checkpoint_interface.h"
#include "main/dll/dll_80220608_shared.h"
#include "main/dll/DR/DRcloudcage.h"
extern int fn_801EC870(int p1, int p2);
extern int hitDetectFn_800658a4(int a, f32 b, f32 val, f32 d, f32* out, int e);
extern f32 lbl_803E5AE8; /* 0.0f  */
extern f32 lbl_803E5AEC; /* 1.0f  */
extern f32 lbl_803E5B08; /* 70.0f */
extern f32 lbl_803E5B10; /* 40.0f */
extern f32 lbl_803E5B68; /* 180.0f */
extern f32 lbl_803E5B6C; /* 56.0f */
extern f32 lbl_803E5B70; /* -1.0f */
extern f32 lbl_803E5B74; /* -0.05f */
extern f32 lbl_803E5B78; /* 2.0f */

#define DRSHACKLE_MODEL_OFFSET 0x54

STATIC_ASSERT(offsetof(ShackleSwingState, anchorX) == 0x0C);
STATIC_ASSERT(offsetof(ShackleSwingState, collider) == 0x28);
STATIC_ASSERT(offsetof(ShackleSwingState, colliderMode) == 0x5D);
STATIC_ASSERT(offsetof(ShackleSwingState, attachment) == 0x178);
STATIC_ASSERT(offsetof(ShackleSwingState, distanceFade) == 0x3E4);
STATIC_ASSERT(offsetof(ShackleSwingState, yaw) == 0x40C);
STATIC_ASSERT(offsetof(ShackleSwingState, targetYaw) == 0x40E);
STATIC_ASSERT(offsetof(ShackleSwingState, flags) == 0x428);
STATIC_ASSERT(offsetof(ShackleSwingState, swingAccel) == 0x430);
STATIC_ASSERT(offsetof(ShackleSwingState, floorAdjustFlag) == 0x434);
STATIC_ASSERT(offsetof(ShackleSwingState, swingCommand) == 0x44C);
STATIC_ASSERT(offsetof(ShackleSwingState, swingReturn) == 0x458);
STATIC_ASSERT(offsetof(ShackleSwingState, swingBlend) == 0x45C);
STATIC_ASSERT(offsetof(ShackleSwingState, unk494) == 0x494);
STATIC_ASSERT(offsetof(ShackleSwingState, lastPitch) == 0x49C);

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
    ShackleSwingState* s = (ShackleSwingState*)state;
    int hitResult;
    int yawDelta;
    f32 fade;

    {
        f32 dx = ((GameObject*)obj)->anim.localPosX;
        f32 dz = ((GameObject*)obj)->anim.localPosZ;
        dx = dx - s->anchorX;
        dz = dz - s->anchorZ;
        fade = lbl_803E5B68 - sqrtf(dx * dx + dz * dz);
    }

    if (s->distanceFade != lbl_803E5AE8)
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
        (u8*)state, &s->collider, fade,
        s->colliderMode, 1);

    (*gCheckpointInterface)
        ->getRouteHeading((GameObject*)obj, &s->collider);

    (*gCheckpointInterface)->queueRouteRankItem(
        (CheckpointRankItem*)&s->collider);

    if (hitResult != 0)
    {
        s->swingBlend = lbl_803E5AE8;
        return 0;
    }

    yawDelta = (s32)(u16)
    getAngle(((GameObject*)obj)->anim.localPosX - s->anchorX,
             ((GameObject*)obj)->anim.localPosZ - s->anchorZ) -
        (s32)(u16)s->yaw;
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
        s->swingBlend = (f32)(-blendStep);
    }
    s->swingCommand = 0;
    s->swingBlend = s->swingBlend / lbl_803E5B6C;

    {
        f32 blend = s->swingBlend;
        s->swingBlend =
            (blend < lbl_803E5B70)
                ? lbl_803E5B70
                : ((blend > lbl_803E5AEC) ? lbl_803E5AEC : blend);
    }

    {
        f32 ang = fn_801EA678(obj, state);
        ang = -ang;
        if (s->lastPitch < ang ||
            yawDelta > DRSHACKLE_ANGLE_RETURN_LIMIT || yawDelta < -DRSHACKLE_ANGLE_RETURN_LIMIT)
        {
            s->swingReturn = 0;
        }
        else if (s->lastPitch > ang)
        {
            s->swingReturn = DRSHACKLE_SWING_RETURN_LEFT;
        }
    }
    return 1;
}

int drshackle_updateAttachedPosition(int obj, int state)
{
    ShackleSwingState* s = (ShackleSwingState*)state;
    ShackleFlags* flags;
    int mapBlockIdx;
    int hitResult;
    s16 angle;
    f32 floorOffset;

    flags = &s->flags;
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
                s->unk494 = zero;
                s->unk498 = zero;
            }
            s->lastPitch = -fn_801EA678(obj, state);
            hitResult = DRSHACKLE_ADVANCE_ROUTE(
                (*gCheckpointInterface),
                (u8*)state, &s->collider,
                -s->lastPitch * timeDelta,
                s->colliderMode, 1);
            (*gCheckpointInterface)
                ->getRouteHeading((GameObject*)obj, &s->collider);
            (*gCheckpointInterface)->queueRouteRankItem(
                (CheckpointRankItem*)&s->collider);
            if (hitResult != 0)
            {
                return 0;
            }

            fn_801EC870(obj, state);
            angle = (s16)getAngle(((GameObject*)obj)->anim.localPosX - s->anchorX,
                                  ((GameObject*)obj)->anim.localPosZ - s->anchorZ);
            ((GameObject*)obj)->anim.rotX = angle;
            s->targetYaw = angle;
            s->yaw = angle;
            s->swingAccel = lbl_803E5B74;
            ((GameObject*)obj)->anim.localPosX = s->anchorX;
            ((GameObject*)obj)->anim.localPosY = s->anchorY;
            ((GameObject*)obj)->anim.localPosZ = s->anchorZ;
            (*gPathControlInterface)->attachObject((void*)obj, (void*)s->attachment);
            *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x10) = ((GameObject*)obj)->anim.localPosX;
            *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x14) = ((GameObject*)obj)->anim.localPosY;
            *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x18) = ((GameObject*)obj)->anim.localPosZ;
            *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x1c) = ((GameObject*)obj)->anim.worldPosX;
            *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x20) = ((GameObject*)obj)->anim.worldPosY;
            *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x24) = ((GameObject*)obj)->anim.worldPosZ;

            if (s->floorAdjustFlag == 0)
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
        (u8*)state, &s->collider,
        timeDelta * fn_801EA678(obj, state), s->colliderMode, 1);
    (*gCheckpointInterface)
        ->getRouteHeading((GameObject*)obj, &s->collider);
    (*gCheckpointInterface)->queueRouteRankItem(
        (CheckpointRankItem*)&s->collider);
    if (hitResult != 0)
    {
        return 0;
    }

    angle = (s16)getAngle(((GameObject*)obj)->anim.localPosX - s->anchorX,
                          ((GameObject*)obj)->anim.localPosZ - s->anchorZ);
    ((GameObject*)obj)->anim.rotX = angle;
    ((GameObject*)obj)->anim.localPosX = s->anchorX;
    ((GameObject*)obj)->anim.localPosY = s->anchorY;
    ((GameObject*)obj)->anim.localPosZ = s->anchorZ;
    (*gPathControlInterface)->attachObject((void*)obj, (void*)s->attachment);
    *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x10) = ((GameObject*)obj)->anim.localPosX;
    *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x14) = ((GameObject*)obj)->anim.localPosY;
    *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x18) = ((GameObject*)obj)->anim.localPosZ;
    *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x1c) = ((GameObject*)obj)->anim.worldPosX;
    *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x20) = ((GameObject*)obj)->anim.worldPosY;
    *(f32*)(*(int*)(obj + DRSHACKLE_MODEL_OFFSET) + 0x24) = ((GameObject*)obj)->anim.worldPosZ;
    flags->positionAnchored = 0;
    return 0;
}
