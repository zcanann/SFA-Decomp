/*
 * DLL 71 / 0x47 - path camera mode.
 */
#include "main/dll/dll_0047_cameramodepath.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "game/objects/object.h"
#include "main/camera_interface.h"
#include "main/curve.h"
#include "main/debug.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/rom_curve_interface.h"
#include "main/frame_timing.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/pad.h"
#include "main/vecmath.h"
#include "string.h"

enum CameraModePathCurveType {
    CAMERA_MODE_PATH_CURVE_TYPE_MOVE_8 = 8,
    CAMERA_MODE_PATH_CURVE_TYPE_CONTROL_9 = 9,
    CAMERA_MODE_PATH_CURVE_TYPE_MOVE_1A = 0x1A,
    CAMERA_MODE_PATH_CURVE_TYPE_CONTROL_1B = 0x1B,
};

extern char sPathCamNeedTwoControlPointsError[];

int lbl_803DD564;
CameraModePathState* gCameraModePathState;

RomCurvePathNode* pathcam_walkToPathEnd(RomCurvePathNode* node, int* count, int tag);
void pathcam_findTaggedNodeWindow(RomCurvePathNode* node, int* out, int tag);
f32 pathcam_segmentParam(f32 x, f32 unused, f32 z, int* nodes);

static void pathcam_advanceNodePair(int* nodeId, int* leadNodeId, f32 x, f32 y, f32 z, int tag) {
    RomCurvePathNode* node;
    RomCurvePathNode* linked;
    int noForwardExit;
    int slot;
    int slot2;
    int step;
    int window[4];
    int span;
    int farSpan;
    int settled;
    f32 dist;
    f32 nearThresh;

    node = (RomCurvePathNode*)(*gRomCurveInterface)->getById(*nodeId);
    noForwardExit = 1;
    for (slot = 0; slot < ROM_CURVE_PATH_LINK_COUNT; slot++) {
        if (node->links[slot] > -1 && (node->directionMask & (1 << slot)) == 0) {
            linked = (RomCurvePathNode*)(*gRomCurveInterface)->getById(node->links[slot]);
            if (linked != NULL && (linked->tag0 == tag || linked->tag1 == tag || linked->tag2 == tag)) {
                noForwardExit = 0;
                slot = ROM_CURVE_PATH_LINK_COUNT;
            }
        }
    }
    if (noForwardExit != 0) {
        for (slot = 0; slot < ROM_CURVE_PATH_LINK_COUNT; slot++) {
            if (node->links[slot] > -1 && (node->directionMask & (1 << slot)) != 0) {
                linked = (RomCurvePathNode*)(*gRomCurveInterface)->getById(node->links[slot]);
                if (linked != NULL && (linked->tag0 == tag || linked->tag1 == tag || linked->tag2 == tag)) {
                    *nodeId = node->links[slot];
                    slot = ROM_CURVE_PATH_LINK_COUNT;
                }
            }
        }
    }
    settled = 0;
    nearThresh = 0.0f;
    while (settled == 0) {
        settled = 1;
        node = (RomCurvePathNode*)(*gRomCurveInterface)->getById(*nodeId);
        pathcam_findTaggedNodeWindow(node, window, tag);
        dist = pathcam_segmentParam(x, y, z, window);
        if (dist < nearThresh) {
            if (window[0] > -1) {
                *nodeId = window[0];
                settled = 0;
            }
        } else if (dist > 1.0f) {
            if (window[2] > -1 && window[3] > -1) {
                *nodeId = window[2];
                settled = 0;
            }
        }
    }
    node = (RomCurvePathNode*)(*gRomCurveInterface)->getById(*nodeId);
    pathcam_walkToPathEnd(node, &span, tag);
    node = (RomCurvePathNode*)(*gRomCurveInterface)->getById(*leadNodeId);
    *leadNodeId = pathcam_walkToPathEnd(node, &farSpan, tag)->selfId;
    for (step = 0; step < span; step++) {
        node = (RomCurvePathNode*)(*gRomCurveInterface)->getById(*leadNodeId);
        for (slot2 = 0; slot2 < ROM_CURVE_PATH_LINK_COUNT; slot2++) {
            if (node->links[slot2] > -1 && (node->directionMask & (1 << slot2)) == 0) {
                linked = (RomCurvePathNode*)(*gRomCurveInterface)->getById(node->links[slot2]);
                if (linked != NULL && (linked->tag0 == tag || linked->tag1 == tag || linked->tag2 == tag)) {
                    *leadNodeId = node->links[slot2];
                    slot2 = ROM_CURVE_PATH_LINK_COUNT;
                }
            }
        }
    }
}

RomCurvePathNode* pathcam_walkToPathEnd(RomCurvePathNode* node, int* count, int tag) {
    int slot;
    int done;
    RomCurvePathNode* linked;

    done = 0;
    *count = 0;
    while (done == 0) {
        done = 1;
        if (node->type != CAMERA_MODE_PATH_CURVE_TYPE_CONTROL_1B && node->type != CAMERA_MODE_PATH_CURVE_TYPE_MOVE_1A) {
            for (slot = 0; slot < ROM_CURVE_PATH_LINK_COUNT; slot++) {
                if (node->links[slot] > -1 && (node->directionMask & (1 << slot)) != 0) {
                    linked = (RomCurvePathNode*)(*gRomCurveInterface)->getById(node->links[slot]);
                    if (linked != NULL && (linked->tag0 == tag || linked->tag1 == tag || linked->tag2 == tag)) {
                        node = linked;
                        done = 0;
                        slot = ROM_CURVE_PATH_LINK_COUNT;
                    }
                }
            }
        }
        if (done == 0) {
            (*count)++;
        }
    }
    return node;
}

void pathcam_buildWindowSamples(int* nodeIds, f32* outX, f32* outY, f32* outZ, f32* outRotationX, f32* outRotationY,
                                f32* outRotationZ, f32* outFov);
u32 CameraModePath_updateTransition(CameraObject* camera, u32 flagsIn);

void pathcam_buildWindowSamples(int* nodeIds, f32* outX, f32* outY, f32* outZ, f32* outRotationX, f32* outRotationY,
                                f32* outRotationZ, f32* outFov) {
    f32* angleCursor;
    f32 *writeX, *writeY, *writeZ, *writeRotationX, *writeRotationY, *writeRotationZ, *writeFov;
    RomCurvePathNode* node;
    int fillIndex;
    int nodeIndex;
    int segmentIndex;
    f32* rotationSamples;
    int axisIndex;
    f32 delta, positiveHalfTurn, current, next;
    RomCurvePathNode* windowNodes[4];

    nodeIndex = 0;
    for (; nodeIndex < 4; nodeIndex++) {
        windowNodes[nodeIndex] = (RomCurvePathNode*)(*gRomCurveInterface)->getById(nodeIds[nodeIndex]);
        node = windowNodes[nodeIndex];
        if (node != NULL) {
            outX[nodeIndex] = node->x;
            outY[nodeIndex] = node->y;
            outZ[nodeIndex] = node->z;
            outRotationX[nodeIndex] = (f32)node->sampleA;
            outRotationY[nodeIndex] = (f32)node->sampleB;
            outRotationZ[nodeIndex] = (f32)node->sampleC;
            outFov[nodeIndex] = (f32)node->sampleD;
        }
    }

    if (windowNodes[1] == NULL || windowNodes[2] == NULL) {
        return;
    }
    {
        fillIndex = 0;
        nodeIndex = 0;
        writeX = outX;
        writeY = outY;
        writeZ = outZ;
        writeRotationX = outRotationX;
        writeRotationY = outRotationY;
        writeRotationZ = outRotationZ;
        writeFov = outFov;
        for (; fillIndex < 4; fillIndex++) {
            if (windowNodes[nodeIndex] == NULL) {
                if (fillIndex == 0) {
                    node = windowNodes[1];
                    *writeX = node->x + (node->x - windowNodes[2]->x);
                    *writeY = node->y + (node->y - windowNodes[2]->y);
                    *writeZ = node->z + (node->z - windowNodes[2]->z);
                    *writeRotationX = (f32)(node->sampleA + (node->sampleA - windowNodes[2]->sampleA));
                    *writeRotationY = (f32)(node->sampleB + (node->sampleB - windowNodes[2]->sampleB));
                    *writeRotationZ = (f32)(node->sampleC + (node->sampleC - windowNodes[2]->sampleC));
                    *writeFov = (f32)node->sampleD + ((f32)node->sampleD - (f32)windowNodes[2]->sampleD);
                } else if (fillIndex == 3) {
                    node = windowNodes[2];
                    *writeX = node->x + (node->x - windowNodes[1]->x);
                    *writeY = node->y + (node->y - windowNodes[1]->y);
                    *writeZ = node->z + (node->z - windowNodes[1]->z);
                    *writeRotationX = (f32)(node->sampleA + (node->sampleA - windowNodes[1]->sampleA));
                    *writeRotationY = (f32)(node->sampleB + (node->sampleB - windowNodes[1]->sampleB));
                    *writeRotationZ = (f32)(node->sampleC + (node->sampleC - windowNodes[1]->sampleC));
                    *writeFov = (f32)node->sampleD + ((f32)node->sampleD - (f32)windowNodes[1]->sampleD);
                }
            }
            nodeIndex++;
            writeX++;
            writeY++;
            writeZ++;
            writeRotationX++;
            writeRotationY++;
            writeRotationZ++;
            writeFov++;
        }

        axisIndex = 0;
        do {
            if (axisIndex == 0) {
                rotationSamples = outRotationX;
            } else if (axisIndex == 1) {
                rotationSamples = outRotationY;
            } else {
                rotationSamples = outRotationZ;
            }
            if (rotationSamples != NULL) {
                angleCursor = rotationSamples;
                positiveHalfTurn = 32768.0f;
                segmentIndex = 0;
                while (segmentIndex < 3) {
                    current = angleCursor[0];
                    next = angleCursor[1];
                    delta = current - next;
                    if (delta > positiveHalfTurn || delta < -32768.0f) {
                        if (current < 0.0f) {
                            angleCursor[0] += 65535.0f;
                        } else if (next < 0.0f) {
                            angleCursor[1] += 65535.0f;
                        }
                    }
                    angleCursor++;
                    segmentIndex++;
                }
            }
            axisIndex++;
        } while (axisIndex < 3);
    }
}

void pathcam_findTaggedNodeWindow(RomCurvePathNode* node, int* outNodeIds, int tag) {
    int linkIndex;
    RomCurvePathNode* linkedNode;
    int linkedNodeId;
    int directionFlag;

    outNodeIds[0] = -1;
    outNodeIds[1] = -1;
    outNodeIds[2] = -1;
    outNodeIds[3] = -1;

    if (node == NULL) {
        return;
    }

    outNodeIds[1] = node->selfId;

    linkIndex = 0;
    for (; linkIndex < ROM_CURVE_PATH_LINK_COUNT; linkIndex++) {
        linkedNodeId = node->links[linkIndex];
        if (linkedNodeId > -1) {
            linkedNode = (RomCurvePathNode*)(*gRomCurveInterface)->getById(linkedNodeId);
            if (linkedNode != NULL) {
                if (linkedNode->tag0 == tag || linkedNode->tag1 == tag || linkedNode->tag2 == tag) {
                    directionFlag = node->directionMask & (1 << linkIndex);
                    if (directionFlag != 0) {
                        outNodeIds[0] = node->links[linkIndex];
                    } else if (directionFlag == 0) {
                        outNodeIds[2] = node->links[linkIndex];
                    }
                }
            }
        }
    }

    linkedNodeId = outNodeIds[2];
    if (linkedNodeId > -1) {
        RomCurvePathNode* nextNode = (RomCurvePathNode*)(*gRomCurveInterface)->getById(linkedNodeId);
        if (nextNode != NULL) {
            if (nextNode->tag0 == tag || nextNode->tag1 == tag || nextNode->tag2 == tag) {
                linkIndex = 0;
                for (; linkIndex < ROM_CURVE_PATH_LINK_COUNT; linkIndex++) {
                    linkedNodeId = nextNode->links[linkIndex];
                    if (linkedNodeId > -1) {
                        directionFlag = nextNode->directionMask & (1 << linkIndex);
                        if (directionFlag == 0) {
                            linkedNode = (RomCurvePathNode*)(*gRomCurveInterface)->getById(linkedNodeId);
                            if (linkedNode != NULL) {
                                if (linkedNode->tag0 == tag || linkedNode->tag1 == tag || linkedNode->tag2 == tag) {
                                    outNodeIds[3] = nextNode->links[linkIndex];
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (outNodeIds[1] < 0 || outNodeIds[2] < 0) {
        debugPrintf(sPathCamNeedTwoControlPointsError);
    }
}

f32 pathcam_segmentParam(f32 x, f32 unusedY, f32 z, int* nodeIds) {
    RomCurvePathNode* windowNodes[4];
    int* nodeIdCursor;
    RomCurvePathNode** nodeCursor;
    int nodeIndex;
    f32 dx1;
    f32 dz1;
    f32 psx;
    f32 sx;
    f32 sz;
    f32 nsz;
    f32 nsx;
    f32 nz;
    f32 nx;
    f32 len;
    f32 t1;
    f32 t2;
    f32 negdot;
    f32 p1x;
    f32 p1z;
    for (nodeIndex = 0, nodeIdCursor = nodeIds, nodeCursor = windowNodes; nodeIndex < 4; nodeIndex++) {
        *nodeCursor = (RomCurvePathNode*)(*gRomCurveInterface)->getById(*nodeIdCursor);
        nodeIdCursor++;
        nodeCursor++;
    }
    dx1 = windowNodes[2]->x - windowNodes[1]->x;
    dz1 = windowNodes[2]->z - windowNodes[1]->z;
    if (windowNodes[0] != NULL) {
        psx = windowNodes[1]->x - windowNodes[0]->x;
        sz = windowNodes[1]->z - windowNodes[0]->z;
    } else {
        psx = dx1;
        sz = dz1;
    }
    nx = 0.5f * (psx + dx1);
    nz = 0.5f * (sz + dz1);
    len = sqrtf(nx * nx + nz * nz);
    if (len != 0.0f) {
        nx /= len;
        nz /= len;
    }
    p1x = windowNodes[1]->x;
    p1z = windowNodes[1]->z;
    negdot = nx * p1x + nz * p1z;
    negdot = -negdot;
    t1 = nx * dx1 + nz * dz1;
    if (t1 != 0.0f) {
        t1 = -(negdot + (nx * x + nz * z)) / t1;
    }
    sx = windowNodes[2]->x - p1x;
    sz = windowNodes[2]->z - p1z;
    if (windowNodes[3] != NULL) {
        nsx = windowNodes[3]->x - windowNodes[2]->x;
        nsz = windowNodes[3]->z - windowNodes[2]->z;
    } else {
        nsx = sx;
        nsz = sz;
    }
    nx = 0.5f * (nsx + sx);
    nz = 0.5f * (nsz + sz);
    len = sqrtf(nx * nx + nz * nz);
    if (len != 0.0f) {
        nx /= len;
        nz /= len;
    }
    negdot = nx * windowNodes[2]->x + nz * windowNodes[2]->z;
    negdot = -negdot;
    t2 = nx * dx1 + nz * dz1;
    if (t2 != 0.0f) {
        t2 = -(negdot + (nx * x + nz * z)) / t2;
    }
    return -t1 / (t2 - t1);
}

void CameraModePath_startTransition(f32 fovEnd, CameraObject* camera, f32* posEnd, s32 rotationXEnd, s32 rotationYEnd,
                                    s32 rotationZEnd);

u32 CameraModePath_updateTransition(CameraObject* camera, u32 flagsIn) {
    u8 flags;
    f32 speed;
    f32 t;

    gCameraModePathState->positionEndX = camera->anim.localPosX;
    gCameraModePathState->positionEndY = camera->anim.localPosY;
    gCameraModePathState->positionEndZ = camera->anim.localPosZ;
    gCameraModePathState->rotationXEnd = camera->anim.rotX;
    gCameraModePathState->rotationYEnd = camera->anim.rotY;
    gCameraModePathState->rotationZEnd = camera->anim.rotZ;
    gCameraModePathState->fovEnd = camera->fov;

    if (gCameraModePathState->transitionDuration != 0.0f) {
        speed = gCameraModePathState->transitionElapsed / gCameraModePathState->transitionDuration;
    } else {
        speed = 0.0f;
    }
    if (speed > 1.0f) {
        speed = 1.0f;
    }
    speed = Curve_EvalHermite(gCameraModePathState->transitionCurve, speed, 0x0);
    if (speed < 0.2f) {
        speed = 0.2f;
    }
    gCameraModePathState->transitionElapsed += speed * timeDelta;

    t = 0.0f;
    if (t != gCameraModePathState->transitionDuration) {
        t = gCameraModePathState->transitionElapsed / gCameraModePathState->transitionDuration;
    }
    if (t > 1.0f) {
        t = 1.0f;
    }
    camera->anim.localPosX = Curve_EvalLinear(&gCameraModePathState->positionStartX, t, NULL);
    camera->anim.localPosY = Curve_EvalLinear(&gCameraModePathState->positionStartY, t, NULL);
    camera->anim.localPosZ = Curve_EvalLinear(&gCameraModePathState->positionStartZ, t, NULL);
    camera->fov = Curve_EvalLinear(&gCameraModePathState->fovStart, t, NULL);

    if (((gCameraModePathState->rotationXStart - gCameraModePathState->rotationXEnd) > 32768.0f) ||
        ((gCameraModePathState->rotationXStart - gCameraModePathState->rotationXEnd) < -32768.0f)) {
        if (gCameraModePathState->rotationXStart < 0.0f) {
            gCameraModePathState->rotationXStart += 65535.0f;
        } else if (gCameraModePathState->rotationXEnd < 0.0f) {
            gCameraModePathState->rotationXEnd += 65535.0f;
        }
    }
    if (((gCameraModePathState->rotationYStart - gCameraModePathState->rotationYEnd) > 32768.0f) ||
        ((gCameraModePathState->rotationYStart - gCameraModePathState->rotationYEnd) < -32768.0f)) {
        if (gCameraModePathState->rotationYStart < 0.0f) {
            gCameraModePathState->rotationYStart += 65535.0f;
        } else if (gCameraModePathState->rotationYEnd < 0.0f) {
            gCameraModePathState->rotationYEnd += 65535.0f;
        }
    }
    if (((gCameraModePathState->rotationZStart - gCameraModePathState->rotationZEnd) > 32768.0f) ||
        ((gCameraModePathState->rotationZStart - gCameraModePathState->rotationZEnd) < -32768.0f)) {
        if (gCameraModePathState->rotationZStart < 0.0f) {
            gCameraModePathState->rotationZStart += 65535.0f;
        } else if (gCameraModePathState->rotationZEnd < 0.0f) {
            gCameraModePathState->rotationZEnd += 65535.0f;
        }
    }

    flags = flagsIn;
    if ((flags & CAMERA_MODE_PATH_TRACK_ROT_X) == 0) {
        camera->anim.rotX = Curve_EvalLinear(&gCameraModePathState->rotationXStart, t, NULL);
    }
    if ((flags & CAMERA_MODE_PATH_TRACK_ROT_Y) == 0) {
        camera->anim.rotY = Curve_EvalLinear(&gCameraModePathState->rotationYStart, t, NULL);
    }
    if ((flags & CAMERA_MODE_PATH_TRACK_ROT_Z) == 0) {
        camera->anim.rotZ = Curve_EvalLinear(&gCameraModePathState->rotationZStart, t, NULL);
    }
    return t >= 1.0f;
}

void CameraModePath_startTransition(f32 fovEnd, CameraObject* camera, f32* posEnd, s32 rotationXEnd, s32 rotationYEnd,
                                    s32 rotationZEnd) {
    f32 dx;
    f32 dy;
    f32 dz;

    gCameraModePathState->transitionComplete = 0;
    gCameraModePathState->positionStartX = camera->anim.localPosX;
    gCameraModePathState->positionStartY = camera->anim.localPosY;
    gCameraModePathState->positionStartZ = camera->anim.localPosZ;
    gCameraModePathState->rotationXStart = (f32)(s32)camera->anim.rotX;
    gCameraModePathState->rotationYStart = (f32)(s32)camera->anim.rotY;
    gCameraModePathState->rotationZStart = (f32)(s32)camera->anim.rotZ;
    gCameraModePathState->fovStart = camera->fov;
    gCameraModePathState->positionEndX = posEnd[0];
    gCameraModePathState->positionEndY = posEnd[1];
    gCameraModePathState->positionEndZ = posEnd[2];
    gCameraModePathState->rotationXEnd = rotationXEnd;
    gCameraModePathState->rotationYEnd = rotationYEnd;
    gCameraModePathState->rotationZEnd = rotationZEnd;
    gCameraModePathState->fovEnd = fovEnd;
    gCameraModePathState->transitionElapsed = 0.0f;
    dx = gCameraModePathState->positionEndX - gCameraModePathState->positionStartX;
    dy = gCameraModePathState->positionEndY - gCameraModePathState->positionStartY;
    dz = gCameraModePathState->positionEndZ - gCameraModePathState->positionStartZ;
    gCameraModePathState->transitionDuration = sqrtf(dx * dx + dy * dy + dz * dz);
    (*gCameraInterface)
        ->initialise(gCameraModePathState->transitionDuration, gCameraModePathState->transitionCurve, 100.0f, 0.1f,
                     0.1f, -5.0f);
}

void CameraModePath_copyToCurrent(void) {
}

void CameraModePath_free(void) {
    mm_free(gCameraModePathState);
    gCameraModePathState = NULL;
}

void CameraModePath_update(CameraObject* cam) {
    int trackRotationZ;
    GameObject* obj;
    int trackRotationX;
    int trackRotationY;
    RomCurvePathNode* node;
    int flags;
    f32 t;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 param;
    int yaw;
    RomCurvePathNode* node2;
    int controlWindow[4];
    int moveWindow[4];
    f32 x[4];
    f32 y[4];
    f32 z[4];
    f32 rotationXSamples[4];
    f32 rotationYSamples[4];
    f32 rotationZSamples[4];
    f32 fov[4];

    if (gCameraModePathState->pathFailed != 0) {
        (*gCameraInterface)->setMode(CAMCONTROL_ACTION_DEFAULT, 0, 1, 0, NULL, 0, 0xff);
    } else {
        obj = cam->anim.targetObj;
        getButtonsJustPressed(0);
        node = (RomCurvePathNode*)(*gRomCurveInterface)->getById(gCameraModePathState->controlNodeId);
        node2 = (RomCurvePathNode*)(*gRomCurveInterface)->getById(gCameraModePathState->moveNodeId);
        pathcam_findTaggedNodeWindow(node2, moveWindow, gCameraModePathState->pathTag);
        pathcam_findTaggedNodeWindow(node, controlWindow, gCameraModePathState->pathTag);
        pathcam_buildWindowSamples(moveWindow, x, y, z, rotationXSamples, rotationYSamples, rotationZSamples, fov);
        param = pathcam_segmentParam(obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ, controlWindow);
        if (param < 0.0f) {
            if (controlWindow[0] > -1) {
                gCameraModePathState->controlNodeId = controlWindow[0];
                node2 = (RomCurvePathNode*)(*gRomCurveInterface)->getById(gCameraModePathState->controlNodeId);
                pathcam_findTaggedNodeWindow(node2, controlWindow, gCameraModePathState->pathTag);
                if (moveWindow[0] > -1) {
                    gCameraModePathState->moveNodeId = moveWindow[0];
                    node2 = (RomCurvePathNode*)(*gRomCurveInterface)->getById(gCameraModePathState->moveNodeId);
                    pathcam_findTaggedNodeWindow(node2, moveWindow, gCameraModePathState->pathTag);
                    pathcam_buildWindowSamples(moveWindow, x, y, z, rotationXSamples, rotationYSamples,
                                               rotationZSamples, fov);
                    param = pathcam_segmentParam(obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ,
                                                 controlWindow);
                    gCameraModePathState->pathProgress += 1.0f;
                } else {
                    param = 0.0f;
                }
            } else {
                param = 0.0f;
            }
        } else if (param > 1.0f) {
            if (controlWindow[2] > -1 && controlWindow[3] > -1) {
                gCameraModePathState->controlNodeId = controlWindow[2];
                node2 = (RomCurvePathNode*)(*gRomCurveInterface)->getById(gCameraModePathState->controlNodeId);
                pathcam_findTaggedNodeWindow(node2, controlWindow, gCameraModePathState->pathTag);
                if (moveWindow[2] > -1 && moveWindow[3] > -1) {
                    gCameraModePathState->moveNodeId = moveWindow[2];
                    node2 = (RomCurvePathNode*)(*gRomCurveInterface)->getById(gCameraModePathState->moveNodeId);
                    pathcam_findTaggedNodeWindow(node2, moveWindow, gCameraModePathState->pathTag);
                    pathcam_buildWindowSamples(moveWindow, x, y, z, rotationXSamples, rotationYSamples,
                                               rotationZSamples, fov);
                    param = pathcam_segmentParam(obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ,
                                                 controlWindow);
                    gCameraModePathState->pathProgress -= 1.0f;
                } else {
                    param = 1.0f;
                }
            } else {
                param = 1.0f;
            }
        }
        t = 0.3f * (param - gCameraModePathState->pathProgress) + gCameraModePathState->pathProgress;
        gCameraModePathState->pathProgress = t;
        cam->anim.worldPosX = Curve_EvalBSpline(x, t, 0);
        cam->anim.worldPosY = Curve_EvalBSpline(y, t, 0);
        cam->anim.worldPosZ = Curve_EvalBSpline(z, t, 0);
        node2 = (RomCurvePathNode*)(*gRomCurveInterface)->getById(gCameraModePathState->moveNodeId);
        flags = node2->cameraFlags;
        trackRotationX = flags & CAMERA_MODE_PATH_TRACK_ROT_X;
        if (trackRotationX == 0) {
            cam->anim.rotX = (int)Curve_EvalCatmullRom(rotationXSamples, t, 0) + 0x8000;
        }
        trackRotationY = flags & CAMERA_MODE_PATH_TRACK_ROT_Y;
        if (trackRotationY == 0) {
            cam->anim.rotY = Curve_EvalCatmullRom(rotationYSamples, t, 0);
        }
        trackRotationZ = flags & CAMERA_MODE_PATH_TRACK_ROT_Z;
        if (trackRotationZ == 0) {
            cam->anim.rotZ = Curve_EvalCatmullRom(rotationZSamples, t, 0);
        }
        cam->fov = Curve_EvalBSpline(fov, t, 0);
        if (gCameraModePathState->transitionComplete == 0 &&
            (s32)CameraModePath_updateTransition(cam, (u32)flags) != 0) {
            gCameraModePathState->transitionComplete = 1;
        }
        dx = cam->anim.worldPosX - obj->anim.worldPosX;
        dy = cam->anim.worldPosY - obj->anim.worldPosY;
        dz = cam->anim.worldPosZ - obj->anim.worldPosZ;
        if (trackRotationX != 0) {
            cam->anim.rotX = 0x8000 - getAngle(dx, dz);
        }
        if (trackRotationY != 0) {
            int delta;
            yaw = getAngle(dy, sqrtf(dx * dx + dz * dz)) & 0xffff;
            delta = (int)(((f32)yaw - Curve_EvalCatmullRom(rotationYSamples, t, 0)) - (f32)(cam->anim.rotY & 0xffff));
            if (delta > 0x8000) {
                delta -= 0xffff;
            }
            if (delta < -0x8000) {
                delta += 0xffff;
            }
            cam->anim.rotY += ((int)(delta * framesThisStep) >> 3);
        }
        if (trackRotationZ != 0) {
            int delta = cam->anim.rotZ - (obj->anim.rotZ & 0xffff);
            if (delta > 0x8000) {
                delta -= 0xffff;
            }
            if (delta < -0x8000) {
                delta += 0xffff;
            }
            cam->anim.rotZ += ((int)(delta * framesThisStep) >> 3);
        }
        if (gCameraModePathState->linkedTransform != NULL) {
            f32 v;
            v = cam->anim.worldPosX;
            gCameraModePathState->linkedTransform->worldPosX = v;
            gCameraModePathState->linkedTransform->localPosX = v;
            v = cam->anim.worldPosY;
            gCameraModePathState->linkedTransform->worldPosY = v;
            gCameraModePathState->linkedTransform->localPosY = v;
            v = cam->anim.worldPosZ;
            gCameraModePathState->linkedTransform->worldPosZ = v;
            gCameraModePathState->linkedTransform->localPosZ = v;
        }
        Obj_TransformWorldPointToLocal(cam->anim.worldPosX, cam->anim.worldPosY, cam->anim.worldPosZ,
                                       &cam->anim.localPosX, &cam->anim.localPosY, &cam->anim.localPosZ,
                                       (GameObject*)cam->anim.parent);
    }
}

void CameraModePath_init(CameraObject* cam, int mode, CameraModePathSettings* settings) {
    RomCurvePathNode* moveNode;
    GameObject* obj;
    RomCurvePathNode* controlNode;
    s16 rotationX;
    s16 rotationY;
    s16 rotationZ;
    f32 t;
    f32 px;
    f32 py;
    f32 pz;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 fov;
    f32 targetPosition[3];
    int controlWindow[4];
    int moveWindow[4];
    f32 rotationXSamples[4];
    f32 rotationYSamples[4];
    f32 rotationZSamples[4];
    f32 fovSamples[4];
    f32 xSamples[4];
    f32 ySamples[4];
    f32 zSamples[4];
    int tags[2];

    obj = cam->anim.targetObj;
    if (gCameraModePathState == 0) {
        gCameraModePathState = (CameraModePathState*)mmAlloc(sizeof(CameraModePathState), 0xf, 0);
    }
    memset(gCameraModePathState, 0, sizeof(CameraModePathState));
    gCameraModePathState->pathTag = settings->pathTag;
    gCameraModePathState->transitionComplete = 1;
    tags[0] = CAMERA_MODE_PATH_CURVE_TYPE_CONTROL_9;
    tags[1] = CAMERA_MODE_PATH_CURVE_TYPE_CONTROL_1B;
    gCameraModePathState->controlNodeId = (*gRomCurveInterface)
                                              ->find(obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ,
                                                     tags, 2, gCameraModePathState->pathTag);
    tags[0] = CAMERA_MODE_PATH_CURVE_TYPE_MOVE_8;
    tags[1] = CAMERA_MODE_PATH_CURVE_TYPE_MOVE_1A;
    gCameraModePathState->moveNodeId = (*gRomCurveInterface)
                                           ->find(obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ, tags,
                                                  2, gCameraModePathState->pathTag);
    pathcam_advanceNodePair(&gCameraModePathState->controlNodeId, &gCameraModePathState->moveNodeId,
                            obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ,
                            gCameraModePathState->pathTag);
    moveNode = (RomCurvePathNode*)(*gRomCurveInterface)->getById(gCameraModePathState->moveNodeId);
    controlNode = (RomCurvePathNode*)(*gRomCurveInterface)->getById(gCameraModePathState->controlNodeId);
    pathcam_findTaggedNodeWindow(moveNode, moveWindow, gCameraModePathState->pathTag);
    pathcam_findTaggedNodeWindow(controlNode, controlWindow, gCameraModePathState->pathTag);
    pathcam_buildWindowSamples(moveWindow, xSamples, ySamples, zSamples, rotationXSamples, rotationYSamples,
                               rotationZSamples, fovSamples);
    t = pathcam_segmentParam(obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ, controlWindow);
    if (t < 0.0f) {
        t = 0.0f;
    } else if (t > 1.0f) {
        t = 1.0f;
    }
    px = Curve_EvalBSpline(xSamples, t, 0);
    py = Curve_EvalBSpline(ySamples, t, 0);
    pz = Curve_EvalBSpline(zSamples, t, 0);
    dx = px - obj->anim.worldPosX;
    dy = py - obj->anim.worldPosY;
    dz = pz - obj->anim.worldPosZ;
    if ((moveNode->cameraFlags & CAMERA_MODE_PATH_TRACK_ROT_X) != 0) {
        rotationX = (s16)(0x8000 - getAngle(dx, dz));
    } else {
        rotationX = (s16)((int)Curve_EvalCatmullRom(rotationXSamples, t, 0) + 0x8000);
    }
    if ((moveNode->cameraFlags & CAMERA_MODE_PATH_TRACK_ROT_Z) != 0) {
        rotationZ = obj->anim.rotZ;
    } else {
        rotationZ = Curve_EvalCatmullRom(rotationZSamples, t, 0);
    }
    if ((moveNode->cameraFlags & CAMERA_MODE_PATH_TRACK_ROT_Y) != 0) {
        rotationY = (s16)getAngle(dy, sqrtf(dx * dx + dz * dz));
        rotationY = (f32)rotationY - Curve_EvalCatmullRom(rotationYSamples, t, 0);
    } else {
        rotationY = Curve_EvalCatmullRom(rotationYSamples, t, 0);
    }
    fov = Curve_EvalBSpline(fovSamples, t, 0);
    targetPosition[0] = px;
    targetPosition[1] = py;
    targetPosition[2] = pz;
    if (settings->skipTransition == 0 && mode != 3) {
        CameraModePath_startTransition(fov, cam, targetPosition, rotationX, rotationY, rotationZ);
    } else {
        cam->anim.worldPosX = px;
        cam->anim.worldPosY = py;
        cam->anim.worldPosZ = pz;
        Obj_TransformWorldPointToLocal(cam->anim.worldPosX, cam->anim.worldPosY, cam->anim.worldPosZ,
                                       &cam->anim.localPosX, &cam->anim.localPosY, &cam->anim.localPosZ,
                                       (GameObject*)cam->anim.parent);
        cam->anim.rotX = rotationX;
        cam->anim.rotY = rotationY;
        cam->anim.rotZ = rotationZ;
        cam->fov = fov;
    }
    gCameraModePathState->pathProgress = t;
}

void CameraModePath_release(void) {
}

void CameraModePath_initialise(void) {
}

CameraModePathDescriptor gCameraModePathDescriptor = {
    {0x00000000, 0x00000000, 0x00000000, 0x00060000},
    CameraModePath_initialise,
    CameraModePath_release,
    NULL,
    CameraModePath_init,
    CameraModePath_update,
    CameraModePath_free,
    CameraModePath_copyToCurrent,
};

char sPathCamNeedTwoControlPointsError[] = "PATHCAM error: need at least two control points\n";
