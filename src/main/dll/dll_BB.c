#include "main/dll/CAM/camcontrol.h"
#include "main/dll/dll_BB.h"

extern void Obj_UpdateWorldTransform(void* obj);
extern void Camera_SetCurrentViewIndex(s32 index);
extern void Camera_UpdateViewMatrices(void);
extern s32 Camera_GetViewportYOffset(void);
extern void Camera_SetFovY(f32 fovY);
extern f32 interpolate(f32 cur, f32 target, f32 t);
extern void loadMapForCameraPos(f32 x, f32 y, f32 z);
extern void OSReport(const char* fmt, ...);
extern void PSVECSubtract(f32 * a, f32 * b, f32 * out);
extern void PSVECNormalize(f32 * src, f32 * dst);
extern f32 PSVECMag(f32 * v);
extern CameraViewSlot* Camera_GetCurrentViewSlot(void);
extern f32 Camera_GetFovY(void);
extern void Camera_SetViewportYOffset(s32 yOffset);
extern void mm_free(void* ptr);
extern void camcontrol_activateHandler(u32 actionId, void* actionData);

extern s16 lbl_803DD4C0;
extern char sDllBBTimeDebugFormat[];
extern f64 lbl_803E1650;
extern f32 timeDelta;
extern f32 lbl_803DD4D0;
extern f32 lbl_803E162C;
extern f32 lbl_803E1630;
extern f32 lbl_803E1668;
extern f32 lbl_803E166C;

/*
 * --INFO--
 *
 * Function: camcontrol_applyState
 * EN v1.0 Address: 0x80101980
 * EN v1.0 Size: 1332b
 * EN v1.1 Address: 0x80101C1C
 * EN v1.1 Size: 1340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_applyState(short* camObj)
{
    float fa;
    float fb;
    short* viewSlot;
    int val;
    float dist;
    float step;
    float delta[3];

    Camera_SetCurrentViewIndex(0);
    viewSlot = (short*)Camera_GetCurrentViewSlot();
    *viewSlot = *camObj;
    viewSlot[1] = camObj[1];
    viewSlot[2] = camObj[2];
    if ((*(byte*)((int)camObj + 0x143) >> 7 & 1) != 0u)
    {
        PSVECSubtract((float*)(camObj + 0xc), (float*)(viewSlot + 6), delta);
        dist = PSVECMag(delta);
        if (dist > lbl_803E1630)
        {
            PSVECNormalize(delta, delta);
        }
        step = interpolate(dist, lbl_803E1668, timeDelta);
        dist = (step < lbl_803E1630)
                    ? lbl_803E1630
                    : ((step > lbl_803E166C * timeDelta) ? lbl_803E166C * timeDelta : step);
        *(float*)(viewSlot + 6) = dist * delta[0] + *(float*)(viewSlot + 6);
        *(float*)(viewSlot + 8) = dist * delta[1] + *(float*)(viewSlot + 8);
        *(float*)(viewSlot + 10) = dist * delta[2] + *(float*)(viewSlot + 10);
    }
    else
    {
        *(float*)(viewSlot + 6) = *(float*)(camObj + 0xc);
        *(float*)(viewSlot + 8) = *(float*)(camObj + 0xe);
        *(float*)(viewSlot + 10) = *(float*)(camObj + 0x10);
    }
    fb = lbl_803E1630;
    lbl_803DD4D0 = *(float*)(camObj + 0x5a);
    if (lbl_803E1630 < *(float*)(camObj + 0x7a))
    {
        *(float*)(camObj + 0x7a) =
            -(*(float*)(camObj + 0x7c) * timeDelta - *(float*)(camObj + 0x7a));
        fa = *(float*)(camObj + 0x7a);
        fb = (fa < fb) ? fb : ((fa > lbl_803E162C) ? lbl_803E162C : fa);
        *(float*)(camObj + 0x7a) = fb;
        if (pCamera[0x139] == '\x02')
        {
            fb = *(float*)(camObj + 0x7a);
            dist = lbl_803E162C - fb * fb * fb;
        }
        else if (pCamera[0x139] == '\x01')
        {
            dist = lbl_803E162C - *(float*)(camObj + 0x7a) * *(float*)(camObj + 0x7a);
        }
        else
        {
            dist = lbl_803E162C - *(float*)(camObj + 0x7a);
        }
        step = (dist < lbl_803E1630) ? lbl_803E1630 : ((dist > lbl_803E162C) ? lbl_803E162C : dist);
        if ((*(byte*)((int)camObj + 0x13f) & 8) != 0)
        {
            *(float*)(viewSlot + 6) =
                step * (*(float*)(viewSlot + 6) - *(float*)(camObj + 0x86)) +
                *(float*)(camObj + 0x86);
        }
        if ((*(byte*)((int)camObj + 0x13f) & 0x10) != 0)
        {
            *(float*)(viewSlot + 8) =
                step * (*(float*)(viewSlot + 8) - *(float*)(camObj + 0x88)) +
                *(float*)(camObj + 0x88);
        }
        if ((*(byte*)((int)camObj + 0x13f) & 0x20) != 0)
        {
            *(float*)(viewSlot + 10) =
                step * (*(float*)(viewSlot + 10) - *(float*)(camObj + 0x8a)) +
                *(float*)(camObj + 0x8a);
        }
        OSReport(sDllBBTimeDebugFormat, step);
        if ((*(byte*)((int)camObj + 0x13f) & 1) != 0)
        {
            camObj[0x80] = camObj[0x83] - *viewSlot;
            if (0x8000 < camObj[0x80])
            {
                camObj[0x80] = camObj[0x80] + 1;
            }
            if (camObj[0x80] < -0x8000)
            {
                camObj[0x80] = camObj[0x80] + -1;
            }
            val = (int)((float)camObj[0x80] * step);
            *viewSlot = camObj[0x83] - (short)val;
        }
        if ((*(byte*)((int)camObj + 0x13f) & 2) != 0)
        {
            camObj[0x81] = camObj[0x84] - viewSlot[1];
            if (0x8000 < camObj[0x81])
            {
                camObj[0x81] = camObj[0x81] + 1;
            }
            if (camObj[0x81] < -0x8000)
            {
                camObj[0x81] = camObj[0x81] + -1;
            }
            val = (int)((float)camObj[0x81] * step);
            viewSlot[1] = camObj[0x84] - (short)val;
        }
        if ((*(byte*)((int)camObj + 0x13f) & 4) != 0)
        {
            camObj[0x82] = camObj[0x85] - viewSlot[2];
            if (0x8000 < camObj[0x82])
            {
                camObj[0x82] = camObj[0x82] + 1;
            }
            if (camObj[0x82] < -0x8000)
            {
                camObj[0x82] = camObj[0x82] + -1;
            }
            val = (int)((float)camObj[0x82] * step);
            viewSlot[2] = camObj[0x85] - (short)val;
        }
    }
    Camera_SetFovY(lbl_803DD4D0);
    Obj_UpdateWorldTransform(viewSlot);
    loadMapForCameraPos(*(float*)(camObj + 0xc), *(float*)(camObj + 0xe),
                        *(float*)(camObj + 0x10));
    val = Camera_GetViewportYOffset();
    lbl_803DD4C0 = (short)val;
    if ((int)lbl_803DD4C0 != (int)*(char*)((int)camObj + 0x13b))
    {
        if ((int)lbl_803DD4C0 < (int)*(char*)((int)camObj + 0x13b))
        {
            lbl_803DD4C0 = lbl_803DD4C0 + (short)*(char*)(camObj + 0x9e) * (short)(int)timeDelta;
            if ((int)*(char*)((int)camObj + 0x13b) < (int)lbl_803DD4C0)
            {
                lbl_803DD4C0 = (short)*(char*)((int)camObj + 0x13b);
            }
        }
        else
        {
            lbl_803DD4C0 = lbl_803DD4C0 - (short)*(char*)(camObj + 0x9e) * (short)(int)timeDelta;
            if ((int)lbl_803DD4C0 < (int)*(char*)((int)camObj + 0x13b))
            {
                lbl_803DD4C0 = (short)*(char*)((int)camObj + 0x13b);
            }
        }
        Camera_SetViewportYOffset(lbl_803DD4C0);
    }
    *(undefined*)((int)camObj + 0x13b) = 0;
    Camera_UpdateViewMatrices();
    return;
}

/*
 * --INFO--
 *
 * Function: camcontrol_applyQueuedAction
 * EN v1.0 Address: 0x80101EBC
 * EN v1.0 Size: 400b
 */
void camcontrol_applyQueuedAction(void)
{
    CameraViewSlot* view;
    float blendStep;

    if (gCamcontrolQueuedActionPending != '\0')
    {
        if (gCamcontrolQueuedActionBlendFrames > 1)
        {
            blendStep = lbl_803E162C / (float)gCamcontrolQueuedActionBlendFrames;
            if ((blendStep <= lbl_803E1630) || (blendStep > lbl_803E162C))
            {
                blendStep = lbl_803E162C;
            }
            *(float*)(pCamera + 0xf4) = lbl_803E162C;
            *(float*)(pCamera + 0xf8) = blendStep;
            pCamera[0x13f] = gCamcontrolQueuedActionMode;
        }
        else
        {
            *(float*)(pCamera + 0xf4) = lbl_803E1630;
            pCamera[0x13f] = 0;
        }
        view = Camera_GetCurrentViewSlot();
        if (lbl_803E162C == *(float*)(pCamera + 0xf4))
        {
            *(float*)(pCamera + 0x10c) = view->x;
            *(float*)(pCamera + 0x110) = view->y;
            *(float*)(pCamera + 0x114) = view->z;
            *(short*)(pCamera + 0x106) = view->yaw;
            *(short*)(pCamera + 0x108) = view->pitch;
            *(short*)(pCamera + 0x10a) = view->roll;
            *(float*)(pCamera + 0x118) = Camera_GetFovY();
        }
        else
        {
            *(short*)pCamera = view->yaw;
            *(short*)(pCamera + 2) = view->pitch;
            *(short*)(pCamera + 4) = view->roll;
            *(float*)(pCamera + 0xb4) = Camera_GetFovY();
        }
        gCamcontrolSavedActionId = gCamcontrolActiveActionId;
        gCamcontrolSavedActionPriority = gCamcontrolActiveActionPriority;
        gCamcontrolSavedActionStartFlags = gCamcontrolActiveActionStartFlags;
        camcontrol_activateHandler((u16)gCamcontrolQueuedActionId, gCamcontrolQueuedActionData);
        gCamcontrolQueuedActionPending = '\0';
        if (gCamcontrolQueuedActionData != (void*)0x0)
        {
            mm_free(gCamcontrolQueuedActionData);
            gCamcontrolQueuedActionData = (void*)0x0;
        }
    }
    return;
}

void Camera_func1D(int param_1)
{
    pCamera[0x141] = (u8)(pCamera[0x141] | ((param_1 << 3) & 0x18));
}

void Camera_func13(int enable)
{
    if (enable != 0)
    {
        pCamera[0x141] = (u8)(pCamera[0x141] | 2);
    }
    else
    {
        pCamera[0x141] = (u8)(pCamera[0x141] & ~2);
    }
}

void Camera_func1C(int flags)
{
    pCamera[0x140] = (u8)(pCamera[0x140] | flags);
}

void Camera_setLetterbox(int yOffset, int applyNow)
{
    if (yOffset > (int)(s8)pCamera[0x13b])
    {
        ((s8*)pCamera)[0x13b] = yOffset;
        pCamera[0x13c] = 2;
        if (applyNow != 0)
        {
            Camera_SetViewportYOffset((s16)yOffset);
        }
    }
    return;
}
