/*
 * cutcam - shared camera collision/avoidance helpers used by the camera
 * mode DLLs (dll_0042..dll_0052).
 *
 * camcontrol_traceMove runs a swept-sphere/bbox trace from one point to
 * another through the world hit-detect system and reports whether the
 * line of sight is clear. camcontrol_traceFromTarget and
 * camcontrol_getTargetPosition build the trace endpoints from a target
 * object's world position (using cameraGetPrevPos2 for class 1 = the
 * player) plus the active CamcontrolModeSettings (cameraMtxVar57) and
 * return the desired camera position / yaw.
 *
 * cameraFn_80103b40 and camMoveFn_80104040 sweep candidate camera
 * positions in fan steps around the target to slide the camera around
 * walls, writing the resulting yaw nudge into
 * cameraMtxVar57->avoidanceYawOffset.
 *
 * camcontrol_updateTargetAction polls the pad and switches camera modes
 * (modes 0x43/0x44/0x49) on lock-on / button input.
 * camcontrol_updateModeSettings interpolates every mode setting along a
 * Hermite curve during a mode transition.
 */
#include "main/dll/CAM/cutCam.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/camcontrol_mode_settings.h"
#include "main/dll/dll_B8.h"
#include "main/object_transform.h"
#include "main/pad.h"
#include "main/curve.h"
#include "sfa_light_decls.h"
extern u16 getPadFn_80014d9c(int controller);
extern int objBboxFn_800640cc(float* p1, float* p2, float* p3, int* p4, int* p5, int p6, int p7, int p8, int p9);
extern void hitDetectFn_80067958(int a, float* b, float* c, int d, int e, int f);
extern void hitDetectFn_800691c0(int a, void* b, int c, int d);
extern void hitDetect_calcSweptSphereBounds(u32* boundsOut, float* startPoints, float* endPoints,
                                            float* radii, int pointCount);
extern int getCurSeqNo();
extern void cameraGetPrevPos2(int obj, f32* x, f32* y, f32* z);
extern int fn_80295C0C(int);     /* gates mode 0x49 (with objFn_80296700) */
extern int objFn_802962b4(int obj);  /* gates mode 0x44 */
extern int objFn_80296700(int obj);  /* gates mode 0x49 (with fn_80295C0C) */
extern float mathSinf(float x);
extern float mathCosf(float x);
extern f64 sqrtf(f64 x);
extern int getAngle(float y, float x);

extern u8 gCutCamBboxBlocked;       /* last bbox-hit result */
extern u8 framesThisStep;
extern f32 lbl_803DD52C;      /* yaw-offset blend gain */
extern f32 lbl_803E1688;      /* collision probe / trace radius */
extern f32 lbl_803E168C;
extern f32 lbl_803E1690;
extern f32 lbl_803E1694;
extern f32 lbl_803E16A0;
extern f32 lbl_803E16A4;
extern f32 lbl_803E16A8;
extern f32 lbl_803E16AC;
extern f32 lbl_803E16B0;
extern f32 lbl_803E16B4;
extern f32 lbl_803E16B8;
extern f32 lbl_803E16BC;
extern f32 lbl_803E16C0;
extern f32 lbl_803E16C4;
extern f32 lbl_803E16C8;
extern f32 lbl_803E16CC;

#pragma dont_inline on
int
camcontrol_traceMove(float* fromPos, float* toPos, float* outPos, u8* traceWork,
                     char traceMode, u8 runTrace, u8 runBbox, float radius)
{
    u8 blocked;
    int clear;
    float endTmp[3];
    u32 sweptBounds[9];

    if (outPos == NULL)
    {
        outPos = endTmp;
    }
    *outPos = *toPos;
    outPos[1] = toPos[1];
    outPos[2] = toPos[2];
    *(float*)(traceWork + CAMCONTROL_TRACE_RADIUS_OFFSET) = radius;
    *(s8*)(traceWork + CAMCONTROL_TRACE_BBOX_HIT_OFFSET) = -1;
    *(s8*)(traceWork + CAMCONTROL_TRACE_MODE_OFFSET) = traceMode;
    *(s16*)(traceWork + CAMCONTROL_TRACE_HIT_COUNT_OFFSET) = 0;
    blocked = 0;
    if (runBbox != 0)
    {
        blocked = objBboxFn_800640cc(fromPos, outPos, (float*)0x1, 0x0, 0x0, 0x10, 0xffffffff, 0xff, 0);
    }
    else
    {
        blocked = 0;
    }
    gCutCamBboxBlocked = blocked;
    if (runTrace != 0)
    {
        hitDetect_calcSweptSphereBounds(sweptBounds, fromPos, outPos,
                                        (float*)(traceWork + CAMCONTROL_TRACE_RADIUS_OFFSET), 1);
        hitDetectFn_800691c0(0, sweptBounds, 0x240, 1);
    }
    hitDetectFn_80067958(0, fromPos, outPos, 1, (int)traceWork, 0);
    clear = 0;
    if ((gCutCamBboxBlocked == 0) && (*(short*)(traceWork + CAMCONTROL_TRACE_HIT_COUNT_OFFSET) == 0))
    {
        clear = 1;
    }
    return clear;
}
#pragma dont_inline reset

u8 camcontrol_traceFromTarget(float* fromPos, GameObject* target, float* outPos)
{
    float targetPos[3];
    u8 traceRec[111];

    if (target->anim.classId == 1)
    {
        cameraGetPrevPos2((int)target, &targetPos[0], &targetPos[1], &targetPos[2]);
    }
    else
    {
        targetPos[0] = target->anim.worldPosX;
        targetPos[1] = target->anim.worldPosY + cameraMtxVar57->targetHeight;
        targetPos[2] = target->anim.worldPosZ;
    }
    camcontrol_traceMove(targetPos, fromPos, outPos, traceRec, 3, '\x01', '\x01', (double)lbl_803E1688);
    return traceRec[CAMCONTROL_TRACE_BLOCKED_OFFSET];
}

u8 camcontrol_getTargetPosition(CameraObject* camera, ObjAnimComponent* targetAnim, f32* outPos,
                                s16* outRotY)
{
    u8 box[112];
    float prev[3];
    float pos[3];
    f32 d2;
    f32 a;
    f32 b;
    f32 c;
    f32 cosv;
    f32 sinv;
    u32 ang;
    int d;

    cosv = mathSinf((lbl_803E168C * targetAnim->rotX) / lbl_803E1690);
    sinv = mathCosf((lbl_803E168C * targetAnim->rotX) / lbl_803E1690);
    d2 = cameraMtxVar57->maxDistance * cameraMtxVar57->maxDistance -
        cameraMtxVar57->lowerHeightOffset * cameraMtxVar57->lowerHeightOffset;
    if (d2 < lbl_803E1694)
    {
        d2 = *(f32*)&lbl_803E1694;
    }
    d2 = sqrtf(d2);
    pos[0] = cosv * d2 + targetAnim->worldPosX;
    pos[1] = cameraMtxVar57->lowerHeightOffset +
        (targetAnim->worldPosY + cameraMtxVar57->targetHeight);
    pos[2] = sinv * d2 + targetAnim->worldPosZ;
    if (targetAnim->classId == 1)
    {
        cameraGetPrevPos2((int)targetAnim, &prev[0], &prev[1], &prev[2]);
    }
    else
    {
        prev[0] = targetAnim->worldPosX;
        prev[1] = targetAnim->worldPosY + cameraMtxVar57->targetHeight;
        prev[2] = targetAnim->worldPosZ;
    }
    camcontrol_traceMove(prev, pos, outPos, box, 3, '\x01', '\x01', lbl_803E1688);
    ((void (*)(int, f32*, f32*, f32*, f32*, f32, int))(*gCameraInterface)->getRelativePosition)(
        (int)camera, &a, &b, &c, &d2, cameraMtxVar57->targetHeight, 0);
    b = camera->anim.worldPosY - (targetAnim->worldPosY + cameraMtxVar57->targetHeight);
    ang = getAngle(b, d2);
    d = ang & 0xffff;
    d -= (u16)camera->anim.rotY;
    if (0x8000 < d)
    {
        d = d - 0xffff;
    }
    if (d < -0x8000)
    {
        d = d + 0xffff;
    }
    if (outRotY != NULL)
    {
        *outRotY = camera->anim.rotY + d;
    }
    return box[CAMCONTROL_TRACE_BLOCKED_OFFSET];
}

void camcontrol_updateTargetAction(CameraObject* camera, GameObject* target)
{
    short classId;
    u16 buttons;
    int cond;
    CamcontrolAction43Payload action43Payload;
    CamcontrolAction44Payload action44Payload;

    if (target->pendingParentObj == NULL)
    {
        buttons = getButtonsJustPressed(0);
        if (camera->currentTarget != NULL)
        {
            classId = ((GameObject*)camera->currentTarget)->anim.classId;
            if (((classId == 0x1c) || (classId == 0x2a)) && (target->anim.classId == 1))
            {
                cond = objFn_80296700((int)target);
                if ((cond != 0) && (cond = fn_80295C0C((int)target), cond != 0))
                {
                    goto action_49;
                }
            }
        }
        if ((camera->targetFlags & 2) != 0)
        {
        action_49:
            cameraSetInterpMode(1);
            (*gCameraInterface)->setMode(0x49, 1, 0, 4, &camera->currentTarget, 0x3c, 0xff);
        }
        else if ((((buttons & 0x10) != 0) && (target->anim.classId == 1)) &&
                 (cond = objFn_802962b4((int)target), cond != 0))
        {
            action44Payload.distance = cameraMtxVar57->minDistance;
            action44Payload.yOffset = cameraMtxVar57->lowerHeightOffset;
            action44Payload.height = cameraMtxVar57->targetHeight;
            cameraSetInterpMode(0);
            (*gCameraInterface)->setMode(0x44, 1, 0, 0xc, &action44Payload, 0xf, 0xfe);
        }
        else
        {
            cond = getCurSeqNo();
            if (((cond == 0) && (buttons = getPadFn_80014d9c(0), (buttons & 0x40) != 0)) &&
                ((camera->anim.flags & 4) == 0))
            {
                action43Payload.action = 5;
                action43Payload.enabled = 1;
                action43Payload.immediate = 1;
                (*gCameraInterface)->setMode(0x43, 1, 0, 4, &action43Payload, 0, 0xff);
            }
        }
    }
}

int cameraFn_80103b40(short* cam, f32* outA, f32* outB, int angle)
{
    int tgt0;
    float probe[75];
    u8 box[136];
    float pathA[21];
    float pathB[21];
    float prev[3];
    f32 spinA;
    f32 spinB;
    f32 spinC;
    f32 spinD;
    int tgt;
    int ang;
    float* pA;
    float* pB;
    float* pp;
    float* pA0;
    float* pB0;
    int result;
    int s;
    int i;
    int found1;
    int found2;
    int dir;
    int d;
    f32 cosv;
    f32 rad;
    f32 dx;
    f32 dz;
    f32 sinv;
    f32 t;
    f32 v;

    OSGetTick();      /* timing probe; return value intentionally unused */
    result = 0;
    ((void (*)(int, f32*, f32*, f32*, f32*, f32, int))(*gCameraInterface)->getRelativePosition)(
        (int)cam, &spinB, &spinC, &spinD, &spinA, cameraMtxVar57->targetHeight, 0);
    tgt0 = *(int*)&((CameraObject*)cam)->anim.targetObj;
    *(int*)&probe[35] = tgt0;
    probe[1] = ((CameraObject*)cam)->anim.worldPosY;
    pathA[0] = ((CameraObject*)cam)->anim.worldPosX;
    pathA[1] = ((CameraObject*)cam)->anim.worldPosY;
    pathA[2] = ((CameraObject*)cam)->anim.worldPosZ;
    pathB[0] = pathA[0];
    pathB[1] = pathA[1];
    pathB[2] = pathA[2];
    if (((GameObject*)tgt0)->anim.classId == 1)
    {
        cameraGetPrevPos2(tgt0, &prev[0], &prev[1], &prev[2]);
    }
    else
    {
        prev[0] = ((GameObject*)tgt0)->anim.worldPosX;
        prev[1] = ((GameObject*)tgt0)->anim.worldPosY + cameraMtxVar57->targetHeight;
        prev[2] = ((GameObject*)tgt0)->anim.worldPosZ;
    }
    s = 0xf;
    i = 0;
    found1 = -1;
    found2 = -1;
    ang = 0xaaa;
    pA0 = pathA;
    pA = pA0;
    pB0 = pathB;
    pB = pB0;
    pp = probe;
    while ((s16)s <= 0x5a)
    {
        if (found1 == -1)
        {
            dx = spinD;
            dz = spinB;
            tgt = *(int*)&((CameraObject*)cam)->anim.targetObj;
            rad = (lbl_803E168C * (f32)(s16)ang) / lbl_803E1690;
            cosv = mathSinf(rad);
            sinv = mathCosf(rad);
            t = dz * sinv - dx * cosv;
            v = t * cosv + dx * sinv;
            t = t + ((GameObject*)tgt)->anim.worldPosX;
            probe[0] = t;
            v = v + ((GameObject*)tgt)->anim.worldPosZ;
            probe[2] = v;
            pA[3] = probe[0];
            pA[4] = probe[1];
            pA[5] = probe[2];
            if (camcontrol_traceMove(prev, pp, NULL, box, 7, '\0', '\0', lbl_803E16A0) != 0)
            {
                found1 = i;
            }
        }
        if (found2 == -1)
        {
            dx = spinD;
            dz = spinB;
            tgt = *(int*)&((CameraObject*)cam)->anim.targetObj;
            rad = (lbl_803E168C * (f32)(s16)(-s * 0xb6)) / lbl_803E1690;
            cosv = mathSinf(rad);
            sinv = mathCosf(rad);
            t = dz * sinv - dx * cosv;
            v = t * cosv + dx * sinv;
            t = t + ((GameObject*)tgt)->anim.worldPosX;
            probe[0] = t;
            v = v + ((GameObject*)tgt)->anim.worldPosZ;
            probe[2] = v;
            pB[3] = probe[0];
            pB[4] = probe[1];
            pB[5] = probe[2];
            if (camcontrol_traceMove(prev, pp, NULL, box, 7, '\0', '\0', lbl_803E16A0) != 0)
            {
                found2 = i;
            }
        }
        pA = pA + 3;
        pB = pB + 3;
        i++;
        ang = ang + 0xaaa;
        s = s + 0xf;
    }
    if (found1 == -1)
    {
        found1 = 6;
    }
    else
    {
        for (i = 0; i <= found1; i++)
        {
            if (camcontrol_traceMove(pA0, pathA + (i + 1) * 3, NULL, box, 7,
                                     '\0', '\0', lbl_803E16A0) == 0)
            {
                found1 = 6;
                break;
            }
            pA0 = pA0 + 3;
        }
    }
    if (found2 == -1)
    {
        found2 = 6;
    }
    else
    {
        for (i = 0; i <= found2; i++)
        {
            if (camcontrol_traceMove(pB0, pathB + (i + 1) * 3, NULL, box, 7,
                                     '\0', '\0', lbl_803E16A0) == 0)
            {
                found2 = 6;
                break;
            }
            pB0 = pB0 + 3;
        }
    }
    dir = 0;
    if (found1 < found2)
    {
        dir = 1;
    }
    else if (found2 < found1)
    {
        dir = -1;
    }
    else if (found1 < 6)
    {
        dir = 1;
    }
    if (dir != 0)
    {
        f32 f;
        f32 g;
        d = (0x8000 - *cam) - (angle & 0xffff);
        if (0x8000 < d)
        {
            d = d - 0xffff;
        }
        if (d < -0x8000)
        {
            d = d + 0xffff;
        }
        if (d < 0)
        {
            d = -d;
        }
        f = ((CameraObject*)cam)->unkC4 * ((CameraObject*)cam)->unkC4;
        if (f < lbl_803E16A4)
        {
            f = lbl_803E16A4;
        }
        g = f * lbl_803E16A8;
        g = lbl_803E16AC + g;
        g = g + d / lbl_803E16B0;
        if (g < lbl_803E16B4)
        {
            g = lbl_803E16B4;
        }
        if (g > lbl_803E16B8)
        {
            g = lbl_803E16B8;
        }
        if (dir == -1)
        {
            g = -g;
        }
        g = g * lbl_803DD52C + cameraMtxVar57->avoidanceYawOffset;
        if (g > lbl_803E16BC)
        {
            g = lbl_803E16BC;
        }
        else if (g < lbl_803E16C0)
        {
            g = lbl_803E16C0;
        }
        cameraMtxVar57->avoidanceYawOffset = g;
        result = 1;
    }
    return result;
}

void camMoveFn_80104040(CameraObject* camera, GameObject* target)
{
    float path[39];
    float endPts[39];
    u8 box[112];
    float radii[13];
    u32 bounds[6];
    float prev[3];
    f32 outB[2];
    f32 outA[2];
    int ang;
    float* p;
    int i;
    int j;
    f32 kB;
    f32 dx;
    f32 kA;
    f32 dz;
    f32 rad;
    f32 sinv;
    f32 cosv;
    f32 t;
    f32 z;
    u8 trace;
    u8 blocked;
    s16 spin;

    Obj_TransformLocalPointToWorld(camera->anim.localPosX, camera->anim.localPosY,
                                   camera->anim.localPosZ, &camera->anim.worldPosX,
                                   &camera->anim.worldPosY, &camera->anim.worldPosZ,
                                   (int)camera->anim.parent);
    gCutCamBboxBlocked = 0;
    if (target->anim.classId == 1)
    {
        cameraGetPrevPos2((int)target, &prev[0], &prev[1], &prev[2]);
    }
    else
    {
        prev[0] = target->anim.worldPosX;
        prev[1] = target->anim.worldPosY + cameraMtxVar57->targetHeight;
        prev[2] = target->anim.worldPosZ;
    }
    path[0] = camera->anim.worldPosX;
    path[1] = camera->anim.worldPosY;
    path[2] = camera->anim.worldPosZ;
    dx = path[0] - prev[0];
    dz = path[2] - prev[2];
    i = 1;
    ang = 0xaaa;
    p = path + 3;
    kA = lbl_803E168C;
    kB = lbl_803E1690;
    do
    {
        rad = (kA * (f32)(s16)ang) / kB;
        cosv = mathSinf(rad);
        sinv = mathCosf(rad);
        t = dx * sinv - dz * cosv;
        z = t * cosv + dz * sinv;
        z = z + target->anim.worldPosZ;
        p[0] = t + target->anim.worldPosX;
        p[1] = camera->anim.worldPosY;
        p[2] = z;
        rad = (kA * (f32)(s16)(-i * 0xaaa)) / kB;
        cosv = mathSinf(rad);
        sinv = mathCosf(rad);
        t = dx * sinv - dz * cosv;
        z = t * cosv + dz * sinv;
        z = z + target->anim.worldPosZ;
        p[3] = t + target->anim.worldPosX;
        p[4] = camera->anim.worldPosY;
        p[5] = z;
        ang = ang + 0x1554;
        p = p + 6;
        i = i + 2;
    }
    while (i <= 0xc);
    for (j = 0; j <= 0xc; j++)
    {
        endPts[j * 3] = prev[0];
        endPts[j * 3 + 1] = prev[1];
        endPts[j * 3 + 2] = prev[2];
        radii[j] = lbl_803E16A0;
    }
    hitDetect_calcSweptSphereBounds(bounds, (float*)path, endPts, radii, 0xd);
    hitDetectFn_800691c0(0, bounds, 0x248, 1);
    trace = camcontrol_traceMove(prev, &camera->anim.worldPosX, NULL, box, 7,
                                 '\0', '\0', lbl_803E16A0);
    blocked = 0;
    if (trace == 0)
    {
        blocked = 1;
    }
    cameraMtxVar57->collisionBlocked = blocked;
    if (blocked != 0)
    {
        cameraMtxVar57->wallAvoidanceFlags.b7 = 0;
        if (cameraFn_80103b40((short*)camera, outA, outB, target->anim.rotX) == 0)
        {
            cameraMtxVar57->avoidanceYawOffset = lbl_803E16AC;
        }
    }
    if (lbl_803E16AC != cameraMtxVar57->avoidanceYawOffset)
    {
        spin = (s16)(int)cameraMtxVar57->avoidanceYawOffset;
        if ((spin < -0x1e) || (0x1e < spin))
        {
            rad = (lbl_803E168C * spin) / lbl_803E1690;
            cosv = mathSinf(rad);
            sinv = mathCosf(rad);
            t = dx * sinv - dz * cosv;
            camera->anim.worldPosX = t + target->anim.worldPosX;
            z = t * cosv + dz * sinv;
            camera->anim.worldPosZ = z + target->anim.worldPosZ;
        }
        cameraMtxVar57->avoidanceYawOffset = cameraMtxVar57->avoidanceYawOffset * lbl_803E16C4;
        if ((cameraMtxVar57->avoidanceYawOffset < lbl_803E16C8) &&
            (cameraMtxVar57->avoidanceYawOffset > lbl_803E16CC))
        {
            cameraMtxVar57->avoidanceYawOffset = lbl_803E16AC;
        }
    }
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY,
                                   camera->anim.worldPosZ, &camera->anim.localPosX,
                                   &camera->anim.localPosY, &camera->anim.localPosZ,
                                   (int)camera->anim.parent);
}

void camcontrol_updateModeSettings(int camera)
{
    f32 blend;
    f32 ratio;
    float curve[4];

    if (cameraMtxVar57->transitionTimer != 0)
    {
        cameraMtxVar57->transitionTimer -= framesThisStep;
        if (cameraMtxVar57->transitionTimer < 0)
        {
            cameraMtxVar57->transitionTimer = 0;
        }
        ratio = (f32)(cameraMtxVar57->transitionDuration -
                cameraMtxVar57->transitionTimer) /
            (f32)(s32)cameraMtxVar57->transitionDuration;
        curve[0] = lbl_803E16AC;
        curve[1] = lbl_803E16A4;
        curve[2] = lbl_803E16AC;
        curve[3] = lbl_803E16AC;
        blend = Curve_EvalHermite(ratio, curve, NULL);
        cameraMtxVar57->targetHeight =
            blend * (cameraMtxVar57->targetTargetHeight - cameraMtxVar57->savedTargetHeight) +
            cameraMtxVar57->savedTargetHeight;
        cameraMtxVar57->minDistance =
            blend * (cameraMtxVar57->targetMinDistance - cameraMtxVar57->savedMinDistance) +
            cameraMtxVar57->savedMinDistance;
        cameraMtxVar57->maxDistance =
            blend * (cameraMtxVar57->targetMaxDistance - cameraMtxVar57->savedMaxDistance) +
            cameraMtxVar57->savedMaxDistance;
        cameraMtxVar57->lowerHeightOffset =
            blend * (cameraMtxVar57->targetLowerHeightOffset -
                cameraMtxVar57->savedLowerHeightOffset) +
            cameraMtxVar57->savedLowerHeightOffset;
        cameraMtxVar57->upperHeightOffset =
            blend * (cameraMtxVar57->targetUpperHeightOffset -
                cameraMtxVar57->savedUpperHeightOffset) +
            cameraMtxVar57->savedUpperHeightOffset;
        cameraMtxVar57->distanceAdjustRate =
            blend * (cameraMtxVar57->targetDistanceAdjustRate -
                cameraMtxVar57->savedDistanceAdjustRate) +
            cameraMtxVar57->savedDistanceAdjustRate;
        cameraMtxVar57->heightAdjustRate =
            blend * (cameraMtxVar57->targetHeightAdjustRate -
                cameraMtxVar57->savedHeightAdjustRate) +
            cameraMtxVar57->savedHeightAdjustRate;
        cameraMtxVar57->slideRightAmount =
            blend * (cameraMtxVar57->targetSlideRightAmount -
                cameraMtxVar57->savedSlideRightAmount) +
            cameraMtxVar57->savedSlideRightAmount;
        cameraMtxVar57->slideLeftAmount =
            blend * (cameraMtxVar57->targetSlideLeftAmount -
                cameraMtxVar57->savedSlideLeftAmount) +
            cameraMtxVar57->savedSlideLeftAmount;
        ((CameraObject*)camera)->fov =
            blend * (cameraMtxVar57->fov - cameraMtxVar57->savedFov) + cameraMtxVar57->savedFov;
    }
}

void doNothing_80103660(int unused)
{
}
