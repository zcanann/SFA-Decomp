#include "main/dll/CAM/attention.h"
#include "main/dll/CAM/camcontrol_mode_settings.h"
#include "main/object_transform.h"

extern int objBboxFn_800640cc(f32* startPoints, f32* endPoints, int radii, int hitOut, int objOut,
                              int pointCount, int mask, int flags, int mode);
extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, int* hitsOut, int pointCount,
                                int mask);
extern void hitDetectFn_80067958(int obj, float* startPoints, float* endPoints, int pointCount,
                                 void* outPos, int mode);
extern void hitDetectFn_800691c0(int obj, uint* bounds, int mask, int flags);
extern void hitDetect_calcSweptSphereBounds(uint* boundsOut, float* startPoints, float* endPoints, float* radii,
                                            int pointCount);
extern f32 lbl_803E1688;
extern f32 lbl_803E16AC;
extern f32 lbl_803E16B4;
extern f32 lbl_803E16D0;
extern f32 lbl_803E16D4;

/*
 * --INFO--
 *
 * Function: camcontrol_updateVerticalBounds
 * EN v1.0 Address: 0x801046F4
 * EN v1.0 Size: 612b
 * EN v1.1 Address: 0x80104990
 * EN v1.1 Size: 700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_updateVerticalBounds(CameraObject* camera, int flags, int param_3, float* upperBound,
                                     float* lowerBound)
{
    float zLim;
    float pt0;
    float zB;
    float diff;
    float bestUpper;
    float bestLower;
    int res;
    int count;
    int i;
    int j;
    int off;
    int off2;
    int camObj;
    int cameraAddr;
    uint bounds[6];
    f32 pos[3];
    int hits;

    cameraAddr = (int)camera;
    camObj = (int)camera->anim.targetObj;
    if ((flags & 1) != 0)
    {
        *(float*)(cameraAddr + 0x74) = lbl_803E1688;
        *(s8*)(cameraAddr + 0x84) = -1;
        *(s8*)(cameraAddr + 0x88) = (s8)param_3;
        res = objBboxFn_800640cc(&camera->probePosX, &camera->anim.worldPosX, 1, 0, 0, 0x10, 0xffffffff, 0xff, 0);
        camera->unk142 = res;
        pos[0] = camera->anim.worldPosX;
        pos[1] = camera->anim.worldPosY;
        pos[2] = camera->anim.worldPosZ;
        hitDetect_calcSweptSphereBounds(bounds, &camera->probePosX, pos, (float*)(cameraAddr + 0x74), 1);
        hitDetectFn_800691c0(camObj, bounds, 0x240, 1);
        hitDetectFn_80067958(camObj, &camera->probePosX, pos, 1, &camera->anim.pad34[0], 0);
        camera->anim.worldPosX = pos[0];
        camera->anim.worldPosY = pos[1];
        camera->anim.worldPosZ = pos[2];
    }
    if ((flags & 2) != 0)
    {
        count = hitDetectFn_80065e50(camObj, camera->anim.worldPosX, camera->anim.worldPosY,
                                     camera->anim.worldPosZ, &hits, 1, 0x40);
        *upperBound = lbl_803E16D0;
        bestUpper = (*lowerBound = lbl_803E16D4);
        bestLower = bestUpper;
        off = 0;
        zLim = lbl_803E16AC;
        for (i = 0; i < count; i++)
        {
            zB = lbl_803E16B4;
            if ((*(float**)(hits + off))[2] < zLim)
            {
                pt0 = **(float**)(hits + off);
                if (pt0 > camera->anim.worldPosY - zB)
                {
                    diff = camera->anim.worldPosY - pt0;
                    if (diff < zLim)
                    {
                        diff = -diff;
                    }
                    if (diff < bestLower)
                    {
                        *lowerBound = pt0;
                        camera->unk12C = (*(float**)(hits + off))[2];
                        bestLower = diff;
                    }
                }
            }
            off += 4;
        }
        off2 = 0;
        zLim = lbl_803E16AC;
        for (j = 0; j < count; j++)
        {
            zB = lbl_803E16B4;
            if ((*(float**)(hits + off2))[2] > zLim)
            {
                pt0 = **(float**)(hits + off2);
                if (pt0 < zB + camera->anim.worldPosY)
                {
                    diff = camera->anim.worldPosY - pt0;
                    if (diff < zLim)
                    {
                        diff = -diff;
                    }
                    if (diff < bestUpper)
                    {
                        *upperBound = pt0;
                        camera->unk130 = (*(float**)(hits + off2))[2];
                        bestUpper = diff;
                    }
                }
            }
            off2 += 4;
        }
    }
    Obj_TransformWorldPointToLocal(camera->anim.worldPosX, camera->anim.worldPosY,
                                   camera->anim.worldPosZ, &camera->anim.localPosX,
                                   &camera->anim.localPosY, &camera->anim.localPosZ,
                                   *(int*)&camera->anim.parent);
}

/*
 * --INFO--
 *
 * Function: CameraModeNormal_func0A
 * EN v1.0 Address: 0x80104958
 * EN v1.0 Size: 88b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeNormal_func0A(float* minDistanceOut, float* maxDistanceOut,
                             float* lowerHeightOffsetOut, float* upperHeightOffsetOut,
                             float* targetHeightOut)
{
    *minDistanceOut = cameraMtxVar57->minDistance;
    *maxDistanceOut = cameraMtxVar57->maxDistance;
    if (lowerHeightOffsetOut != (float*)0x0)
    {
        *lowerHeightOffsetOut = cameraMtxVar57->lowerHeightOffset;
    }
    if (upperHeightOffsetOut != (float*)0x0)
    {
        *upperHeightOffsetOut = cameraMtxVar57->upperHeightOffset;
    }
    if (targetHeightOut != (float*)0x0)
    {
        *targetHeightOut = cameraMtxVar57->targetHeight;
    }
    return;
}
