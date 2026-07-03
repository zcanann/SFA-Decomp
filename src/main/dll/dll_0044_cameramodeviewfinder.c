/*
 * dll_0044_cameramodeviewfinder - the first-person "viewfinder" camera
 * mode (binoculars / spyglass aiming) for the dll_5B camera-mode set.
 *
 * Shares the heap-allocated ViewfinderState (the .sbss pointer
 * lbl_803DD548) with the other dll_5B modes. _init blends the live
 * camera into the viewfinder pose along Hermite curves (posX/Y/Z + yaw
 * curves); _update runs a small state machine over ViewfinderState.mode:
 *   0 enter blend, 1 yaw settle, 2 active look, 3 exit blend, 4 fade
 *   back to gameplay, 5 idle (skip-blend entry).
 * In the active state firstPersonDoControls turns the control stick into
 * yaw/pitch deltas and the C-stick into a zoom (FOV) adjust, and toggles
 * the on-screen viewfinder HUD / zoom SFX. Exit is forced when the look
 * button (0x210) is pressed or ObjHits_GetPriorityHit reports a blocking
 * hit. GameBit 0xC64 selects the zoom-HUD ("binocular") variant.
 *
 * All tunables live in the lbl_803E17C0..gCamViewfinderPi .sdata2 float pool
 * (interpolation rates, clamp limits, FOV span); lbl_803E17C4 is 0.0f.
 */
#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/dll_0045_camTalk.h"
#include "main/dll/CAM/viewfinder_state.h"
#include "main/gamebits.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/objhits.h"
#include "main/pad.h"
#include "main/dll/player_motion.h"
#include "main/dll/player_objects.h"
#include "main/rcp_dolphin.h"
#include "sfa_light_decls.h"
#include "main/audio/sfx_trigger_ids.h"

#define PAD_BUTTON_B 0x200

/* ViewfinderState.mode state machine (see file header) */
#define VIEWFINDER_MODE_ENTER_BLEND 0
#define VIEWFINDER_MODE_YAW_SETTLE 1
#define VIEWFINDER_MODE_ACTIVE 2
#define VIEWFINDER_MODE_EXIT_BLEND 3
#define VIEWFINDER_MODE_FADE_BACK 4
#define VIEWFINDER_MODE_IDLE 5

extern u8 padGetCY(int port);
extern s8 padGetStickX(int port);
extern s8 padGetStickY(int port);
extern u32 getAngle();
extern f32 sqrtf(f32 x);
extern float mathSinf(float x);
extern float mathCosf(float x);
extern f32 interpolate(f32 a, f32 t, f32 exp);

extern void viewFinderSetZoom(f32 fov);

extern void buttonDisable(int port, u32 mask);
extern void firstPersonZoomOutOnExit(int a, int b);
extern void fn_80137948(char* fmt, ...);
extern char sCam5BYDebugFormat;
extern void* memset(void* dst, int v, int n);
extern ViewfinderState* lbl_803DD548;
extern f32 timeDelta;
extern f32 lbl_803E17C0;
extern f32 lbl_803E17C4;
extern f32 lbl_803E17C8;
extern f32 lbl_803E17CC;
extern f32 lbl_803E17D0;
extern f32 lbl_803E17E0;
extern f32 lbl_803E17E4;
extern f32 lbl_803E17E8;
extern f32 lbl_803E17EC;
extern f32 lbl_803E17F0;
extern f32 lbl_803E17F4;
extern f32 lbl_803E17F8;
extern f32 lbl_803E17FC;
extern f32 lbl_803E1800;
extern f32 lbl_803E1804;
extern f32 lbl_803E1808;
extern f32 lbl_803E180C;
extern f32 lbl_803E1810;
extern f32 gCamViewfinderBrightnessScale;
extern f32 lbl_803E1818;
extern f32 lbl_803E181C;
extern f32 lbl_803E1820;
extern f32 lbl_803E1824;
extern f32 lbl_803E1828;
extern f32 lbl_803E182C;
extern f32 lbl_803E1830;
extern f32 gCamViewfinderPi;

void firstPersonDoControls(s16* obj)
{
    short pitchDelta;
    s8 stickX;
    s8 stickY;
    short* camObj;
    int spinI;
    f32 t;
    f32 zoom;
    f32 spin;
    f32 fovTarget;
    f32 zoom2;

    camObj = *(short**)(obj + 0x52);
    stickX = padGetStickX(0);
    stickY = padGetStickY(0);
    t = (lbl_803E17E0 - ((CameraObject*)obj)->fov) / lbl_803E17E4;
    zoom = (t < lbl_803E17C4) ? lbl_803E17C4 : ((t > lbl_803E17E8) ? lbl_803E17E8 : t);
    spin = stickX * -(lbl_803E17F0 * zoom - lbl_803E17EC);
    spin = interpolate(spin - lbl_803DD548->yawSpeed, lbl_803E17F4, timeDelta);
    lbl_803DD548->yawSpeed = lbl_803DD548->yawSpeed + spin;
    if ((lbl_803DD548->yawSpeed > lbl_803E17F8) &&
        (lbl_803DD548->yawSpeed < lbl_803E17FC))
    {
        lbl_803DD548->yawSpeed = lbl_803E17C4;
    }
    spinI = (int)(lbl_803E1800 * ((f32)stickY / lbl_803E1804));
    *obj = lbl_803DD548->yawSpeed * timeDelta + (f32) * obj;
    pitchDelta = spinI - (obj[1] & 0xffffU);
    if (0x8000 < pitchDelta)
    {
        pitchDelta = pitchDelta - 0xffff;
    }
    if (pitchDelta < -0x8000)
    {
        pitchDelta = pitchDelta + 0xffff;
    }
    spin = interpolate((f32)pitchDelta, lbl_803E17E8 / (lbl_803E180C * zoom + lbl_803E1808), timeDelta);
    obj[1] = obj[1] + spin;
    if (0x3c00 < obj[1])
    {
        obj[1] = 0x3c00;
    }
    if (obj[1] < -0x3c00)
    {
        obj[1] = -0x3c00;
    }
    *camObj = 0x8000 - *obj;
    if (camObj[0x22] == 1)
    {
        Player_SetHeading((int)camObj, *camObj);
    }
    if (lbl_803DD548->camPosY < lbl_803DD548->clampedPosY)
    {
        lbl_803DD548->clampedPosY = lbl_803DD548->camPosY;
    }
    ((GameObject*)obj)->anim.worldPosX = lbl_803DD548->camPosX;
    ((GameObject*)obj)->anim.worldPosY = lbl_803DD548->clampedPosY;
    ((GameObject*)obj)->anim.worldPosZ = lbl_803DD548->camPosZ;
    if (lbl_803DD548->flags.zoomHudEnabled)
    {
        zoom2 = ((CameraObject*)obj)->fov;
        stickX = padGetCY(0);
        t = (f32) - stickX;
        t = lbl_803E1810 * t;
        zoom2 = t * timeDelta + zoom2;
        viewFinderSetZoom(Camera_GetFovY());
        fovTarget = (zoom2 < lbl_803E17FC)
                        ? lbl_803E17FC
                        : ((zoom2 > lbl_803E17E0) ? lbl_803E17E0 : zoom2);
        if (lbl_803DD548->flags.sfxEnabled)
        {
            if ((fovTarget == ((CameraObject*)obj)->fov) &&
                (lbl_803DD548->flags.zoomSfxPlaying))
            {
                Sfx_StopFromObject(0, SFXTRIG_and_swipe1);
                lbl_803DD548->flags.zoomSfxPlaying = 0;
            }
            if ((fovTarget != ((CameraObject*)obj)->fov) &&
                (!lbl_803DD548->flags.zoomSfxPlaying))
            {
                Sfx_PlayFromObject(0, SFXTRIG_and_swipe1);
                lbl_803DD548->flags.zoomSfxPlaying = 1;
            }
        }
        ((CameraObject*)obj)->fov = fovTarget;
    }
}

int firstPersonEnter(u8* cam, s16* p2)
{
    f32 f2;
    f32 start;
    f32 end;
    u8* state;
    int conv;
    int flag;
    int other;

    ((CameraObject*)cam)->anim.worldPosX = lbl_803DD548->camPosX;
    ((CameraObject*)cam)->anim.worldPosY = lbl_803DD548->camPosY;
    ((CameraObject*)cam)->anim.worldPosZ = lbl_803DD548->camPosZ;
    ((CameraObject*)cam)->anim.rotY = 0;
    flag = 0;
    if (((CameraObject*)cam)->blendProgress <= lbl_803E17C4)
    {
        flag = 1;
    }
    conv = (int)(gCamViewfinderBrightnessScale * ((CameraObject*)cam)->blendProgress);
    state = ((CameraObject*)cam)->anim.targetObj;
    if (conv < 1)
    {
        conv = 1;
    }
    if (state != NULL)
    {
        state[54] = conv;
        if ((u8*)Obj_GetPlayerObject() == state)
        {
            Player_GetHeldObject((int)state, &other);
            if ((u32)other != 0)
            {
                *(u8*)(other + 54) = conv;
                if (*(u8*)(other + 54) == 1)
                {
                    *(u8*)(other + 54) = 0;
                }
            }
        }
    }
    if (flag != 0)
    {
        lbl_803DD548->viewCurve.px = &lbl_803DD548->yawCurve.start;
        lbl_803DD548->viewCurve.py = NULL;
        lbl_803DD548->viewCurve.pz = NULL;
        lbl_803DD548->viewCurve.count = 4;
        lbl_803DD548->viewCurve.eval = Curve_EvalHermite;
        lbl_803DD548->viewCurve.coeffFn = Curve_BuildHermiteCoeffs;
        lbl_803DD548->viewCurve.dir = 0;
        lbl_803DD548->yawCurve.start = (f32)(s32) * (s16*)cam;
        lbl_803DD548->yawCurve.end = (f32)(s16)(0x8000 - p2[0]);
        start = lbl_803DD548->yawCurve.start;
        end = lbl_803DD548->yawCurve.end;
        f2 = start - end;
        if (f2 < lbl_803E1818 && f2 > lbl_803E181C)
        {
            lbl_803DD548->yawCurve.end = lbl_803DD548->yawCurve.start;
        }
        else if (f2 > lbl_803E17C8 || f2 < lbl_803E17CC)
        {
            if (start < lbl_803E17C4)
            {
                lbl_803DD548->yawCurve.start += lbl_803E17D0;
            }
            else if (end < lbl_803E17C4)
            {
                lbl_803DD548->yawCurve.end += lbl_803E17D0;
            }
        }
        {
            f32 k = lbl_803E17C4;
            lbl_803DD548->yawCurve.startTangent = k;
            lbl_803DD548->yawCurve.endTangent = k;
        }
        curvesMove(&lbl_803DD548->viewCurve);
        return 1;
    }
    return 0;
}

void CameraModeViewfinder_copyToCurrent(s16* camObj)
{
    u8* src = (u8*)camObj;
    u8* cur;

    cur = (u8*)(*gCameraInterface)->getCamera();
    if ((cur != NULL) && (src != NULL))
    {
        *(s16*)(cur + 0) = *(s16*)(src + 0);
        *(s16*)(cur + 2) = *(s16*)(src + 2);
        *(s16*)(cur + 4) = *(s16*)(src + 4);
        *(f32*)(cur + 12) = *(f32*)(src + 8);
        *(f32*)(cur + 16) = *(f32*)(src + 12);
        *(f32*)(cur + 20) = *(f32*)(src + 16);
        *(f32*)(cur + 24) = *(f32*)(src + 8);
        *(f32*)(cur + 28) = *(f32*)(src + 12);
        *(f32*)(cur + 32) = *(f32*)(src + 16);
        *(f32*)(cur + 180) = *(f32*)(src + 20);
    }
}

void CameraModeViewfinder_free(int camObj)
{
    int player;
    int viewObj;
    int outBuf[3];

    *(s16*)(*(int*)(camObj + 0xa4) + 6) &= ~0x4000;
    Rcp_SetViewFinderHudEnabled(0);
    viewObj = *(int*)(camObj + 0xa4);
    if ((u32)viewObj != 0)
    {
        ((GameObject*)viewObj)->anim.alpha = 0xff;
        player = Obj_GetPlayerObject();
        if ((u32)player == viewObj)
        {
            Player_GetHeldObject(viewObj, outBuf);
            if ((u32)outBuf[0] != 0)
            {
                ((GameObject*)outBuf[0])->anim.alpha = 0xff;
                if (((GameObject*)outBuf[0])->anim.alpha == 1)
                {
                    ((GameObject*)outBuf[0])->anim.alpha = 0;
                }
            }
        }
    }
    Sfx_StopFromObject(0, SFXTRIG_and_swipe1);
    mm_free(lbl_803DD548);
    lbl_803DD548 = NULL;
    viewFinderSetZoom(lbl_803E17E0);
}

void CameraModeViewfinder_update(s16* obj)
{
    u8* targetObj;
    int brightness;
    int camObj;
    int angleDiff;
    f32 outA;
    f32 hitY;
    f32 outB;
    f32 hitDist;
    u8* shadow2;
    u8* shadow;

    camObj = *(int*)&((GameObject*)obj)->anim.targetObj;
    getButtonsJustPressed(0);
    firstPersonPlaceCamera((GameObject*)camObj, 0);
    switch (lbl_803DD548->mode)
    {
    case VIEWFINDER_MODE_ENTER_BLEND:
        lbl_803DD548->mode = firstPersonEnter((u8*)obj, (s16*)*(int*)&((GameObject*)obj)->anim.targetObj);
        break;
    case VIEWFINDER_MODE_YAW_SETTLE:
        if (Curve_AdvanceAlongPath(&lbl_803DD548->viewCurve, lbl_803E1820) != 0)
        {
            if (lbl_803DD548->flags.zoomHudEnabled)
            {
                Rcp_SetViewFinderHudEnabled(1);
            }
            lbl_803DD548->mode = VIEWFINDER_MODE_ACTIVE;
        }
        *obj = lbl_803DD548->viewCurve.sample[0];
        ((CameraObject*)obj)->unk13E = 1;
        break;
    case VIEWFINDER_MODE_ACTIVE:
        if (lbl_803DD548->flags.zoomHudEnabled)
        {
            Rcp_SetViewFinderHudEnabled(1);
        }
        firstPersonDoControls(obj);
        if (getButtonsJustPressed(0) & 0x210)
        {
            buttonDisable(0, PAD_BUTTON_B);
            firstPersonExit((CameraObject*)obj);
            Rcp_SetViewFinderHudEnabled(0);
            lbl_803DD548->mode = VIEWFINDER_MODE_EXIT_BLEND;
        }
        ((CameraObject*)obj)->unk13E = 0;
        break;
    case VIEWFINDER_MODE_EXIT_BLEND:
        angleDiff = Curve_AdvanceAlongPath(&lbl_803DD548->viewCurve, lbl_803E1820);
        *obj = lbl_803DD548->viewCurve.sample[0];
        obj[1] = lbl_803DD548->viewCurve.sample[1];
        if (angleDiff != 0)
        {
            lbl_803DD548->viewCurve.px = &lbl_803DD548->posXCurve.start;
            lbl_803DD548->viewCurve.py = &lbl_803DD548->posYCurve.start;
            lbl_803DD548->viewCurve.pz = &lbl_803DD548->posZCurve.start;
            lbl_803DD548->viewCurve.count = 4;
            lbl_803DD548->viewCurve.dir = 0;
            lbl_803DD548->viewCurve.eval = Curve_EvalHermite;
            lbl_803DD548->viewCurve.coeffFn = Curve_BuildHermiteCoeffs;
            curvesMove(&lbl_803DD548->viewCurve);
            *(s16*)(*(int*)&((GameObject*)obj)->anim.targetObj + 6) = *(s16*)(*(int*)&((GameObject*)obj)->anim.targetObj + 6) & ~0x4000;
            firstPersonZoomOutOnExit(0xf, 0xfe);
            lbl_803DD548->mode = VIEWFINDER_MODE_FADE_BACK;
            if (lbl_803DD548->flags.sfxEnabled)
            {
                Sfx_PlayFromObject(0, lbl_803DD548->flags.zoomHudEnabled ? SFXTRIG_and_missilelaunch : SFXTRIG_shop_pricedown);
            }
        }
        ((CameraObject*)obj)->unk13E = 1;
        break;
    case VIEWFINDER_MODE_FADE_BACK:
        ((GameObject*)obj)->anim.worldPosX = lbl_803DD548->posXCurve.end;
        ((GameObject*)obj)->anim.worldPosY = lbl_803DD548->posYCurve.end;
        ((GameObject*)obj)->anim.worldPosZ = lbl_803DD548->posZCurve.end;
        {
            f32 fade = (lbl_803E17E8 - ((CameraObject*)obj)->blendProgress) - lbl_803E1824;
            if (fade < lbl_803E17C4)
            {
                fade = lbl_803E17C4;
            }
            fade = fade * lbl_803E1828;
            if (fade > *(f32*)&lbl_803E17E8)
            {
                fade = *(f32*)&lbl_803E17E8;
            }
            brightness = (int)(gCamViewfinderBrightnessScale * fade);
        }
        targetObj = *(u8**)(obj + 0x52);
        if (brightness < 1)
        {
            brightness = 1;
        }
        if (targetObj != NULL)
        {
            ((GameObject*)targetObj)->anim.alpha = brightness;
            if ((u8*)Obj_GetPlayerObject() == targetObj)
            {
                Player_GetHeldObject((int)targetObj, (int*)&shadow2);
                if (shadow2 != NULL)
                {
                    ((GameObject*)shadow2)->anim.alpha = brightness;
                    if (((GameObject*)shadow2)->anim.alpha == 1)
                    {
                        ((GameObject*)shadow2)->anim.alpha = 0;
                    }
                }
            }
        }
        brightness = 0;
        if (((CameraObject*)obj)->blendProgress <= lbl_803E17C4)
        {
            brightness = 1;
        }
        (*gCameraInterface)->getRelativePosition(lbl_803E17C4, (int)obj, &outA, &hitY,
                                                 &outB, &hitDist, 0);
        if (hitDist < lbl_803E182C)
        {
            obj[1] = 0;
        }
        else
        {
            hitY = ((GameObject*)obj)->anim.worldPosY - (((GameObject*)camObj)->anim.worldPosY + lbl_803E17C0);
            angleDiff = (getAngle() & 0xffff) - (obj[1] & 0xffffU);
            if (angleDiff > 0x8000)
            {
                angleDiff = angleDiff - 0xffff;
            }
            if (angleDiff < -0x8000)
            {
                angleDiff = angleDiff + 0xffff;
            }
            obj[1] = *(s16*)&obj[1] + (int)((f32)angleDiff * timeDelta) / 8;
        }
        if (brightness != 0)
        {
            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
            targetObj = *(u8**)(obj + 0x52);
            if (targetObj != NULL)
            {
                ((GameObject*)targetObj)->anim.alpha = 0xff;
                if ((u8*)Obj_GetPlayerObject() == targetObj)
                {
                    Player_GetHeldObject((int)targetObj, (int*)&shadow);
                    if (shadow != NULL)
                    {
                        ((GameObject*)shadow)->anim.alpha = 0xff;
                        if (((GameObject*)shadow)->anim.alpha == 1)
                        {
                            ((GameObject*)shadow)->anim.alpha = 0;
                        }
                    }
                }
            }
        }
        ((CameraObject*)obj)->unk13E = 1;
        break;
    case VIEWFINDER_MODE_IDLE:
        break;
    }
    if (ObjHits_GetPriorityHit(*(int*)&((GameObject*)obj)->anim.targetObj, 0, 0, 0) != 0)
    {
        firstPersonExit((CameraObject*)obj);
        ((GameObject*)obj)->anim.worldPosX = lbl_803DD548->posXCurve.end;
        ((GameObject*)obj)->anim.worldPosY = lbl_803DD548->posYCurve.end;
        ((GameObject*)obj)->anim.worldPosZ = lbl_803DD548->posZCurve.end;
        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0);
    }
    fn_80137948(&sCam5BYDebugFormat, ((GameObject*)obj)->anim.worldPosY);
    Obj_TransformWorldPointToLocal(((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY, ((GameObject*)obj)->anim.worldPosZ,
                                   (f32*)(obj + 6), (f32*)(obj + 8), (f32*)(obj + 10),
                                   *(int*)&((GameObject*)obj)->anim.parent);
}

void CameraModeViewfinder_init(s16* obj, int mode, int* args)
{
    s16* camObj;
    s16 diff;
    s16 absDiff;
    s16 a2;
    f32 dx;
    f32 dz;
    f32 dist;
    f32 spinRate;
    f32 rollRate;
    f32 cosv;
    f32 sinv;
    f32 zero;

    camObj = *(s16**)(obj + 0x52);
    if (lbl_803DD548 == NULL)
    {
        lbl_803DD548 = mmAlloc(sizeof(ViewfinderState), 0xf, 0);
    }
    memset(lbl_803DD548, 0, sizeof(ViewfinderState));
    *(f32*)lbl_803DD548 = *(f32*)args;
    lbl_803DD548->unk114 = (f32)(u32) * (u16*)((int)args + 8);
    lbl_803DD548->unk4 = *(f32*)(args + 1);
    lbl_803DD548->yawSpeed = lbl_803E17C4;
    diff = 0x8000 - obj[0] - camObj[0];
    if (diff < 0)
    {
        absDiff = -diff;
    }
    else
    {
        absDiff = diff;
    }
    spinRate = diff / lbl_803E17E4;
    rollRate = absDiff / lbl_803E1830;
    lbl_803DD548->viewCurve.px = &lbl_803DD548->posXCurve.start;
    lbl_803DD548->viewCurve.py = &lbl_803DD548->posYCurve.start;
    lbl_803DD548->viewCurve.pz = &lbl_803DD548->posZCurve.start;
    lbl_803DD548->viewCurve.count = 4;
    lbl_803DD548->viewCurve.dir = 0;
    lbl_803DD548->viewCurve.eval = Curve_EvalHermite;
    lbl_803DD548->viewCurve.coeffFn = Curve_BuildHermiteCoeffs;
    dx = ((GameObject*)obj)->anim.worldPosX - *(f32*)(camObj + 0xc);
    dz = ((GameObject*)obj)->anim.worldPosZ - *(f32*)(camObj + 0x10);
    dist = sqrtf(dx * dx + dz * dz);
    if (lbl_803E17C4 != dist)
    {
        dx = dx / dist;
        dz = dz / dist;
    }
    firstPersonPlaceCamera((GameObject*)camObj, 1);
    cosv = -mathSinf((gCamViewfinderPi * camObj[0]) / lbl_803E17C8);
    sinv = -mathCosf((gCamViewfinderPi * camObj[0]) / lbl_803E17C8);
    lbl_803DD548->posXCurve.start = ((GameObject*)obj)->anim.worldPosX;
    lbl_803DD548->posXCurve.end = lbl_803DD548->camPosX;
    lbl_803DD548->posXCurve.startTangent = -dz * spinRate;
    lbl_803DD548->posXCurve.endTangent = cosv * rollRate;
    lbl_803DD548->posYCurve.start = ((GameObject*)obj)->anim.worldPosY;
    lbl_803DD548->posYCurve.end = lbl_803DD548->camPosY;
    zero = lbl_803E17C4;
    lbl_803DD548->posYCurve.startTangent = zero;
    lbl_803DD548->posYCurve.endTangent = zero;
    lbl_803DD548->posZCurve.start = ((GameObject*)obj)->anim.worldPosZ;
    lbl_803DD548->posZCurve.end = lbl_803DD548->camPosZ;
    lbl_803DD548->posZCurve.startTangent = dx * spinRate;
    lbl_803DD548->posZCurve.endTangent = sinv * rollRate;
    lbl_803DD548->posXCurve.startTangent = zero;
    lbl_803DD548->posXCurve.endTangent = zero;
    lbl_803DD548->posYCurve.startTangent = zero;
    lbl_803DD548->posYCurve.endTangent = zero;
    lbl_803DD548->posZCurve.startTangent = zero;
    lbl_803DD548->posZCurve.endTangent = zero;
    curvesMove(&lbl_803DD548->viewCurve);
    a2 = obj[0] - (u16)(0x8000 - getAngle(((GameObject*)obj)->anim.worldPosX - lbl_803DD548->posXCurve.end,
                                              ((GameObject*)obj)->anim.worldPosZ - lbl_803DD548->posZCurve.end));
    if (a2 > 0x8000)
    {
        a2 = a2 - 0xffff;
    }
    if (a2 < -0x8000)
    {
        a2 = a2 + 0xffff;
    }
    lbl_803DD548->yawCurve.start = a2;
    zero = lbl_803E17C4;
    lbl_803DD548->yawCurve.end = zero;
    lbl_803DD548->yawCurve.startTangent = zero;
    lbl_803DD548->yawCurve.endTangent = zero;
    if (lbl_803DD548->yawCurve.start - lbl_803DD548->yawCurve.end > lbl_803E17C8 ||
        lbl_803DD548->yawCurve.start - lbl_803DD548->yawCurve.end < lbl_803E17CC)
    {
        if (lbl_803DD548->yawCurve.start < lbl_803E17C4)
        {
            lbl_803DD548->yawCurve.start += lbl_803E17D0;
        }
        else if (lbl_803DD548->yawCurve.end < lbl_803E17C4)
        {
            lbl_803DD548->yawCurve.end += lbl_803E17D0;
        }
    }
    lbl_803DD548->pitchCurve.start = obj[1];
    zero = lbl_803E17C4;
    lbl_803DD548->pitchCurve.end = zero;
    lbl_803DD548->pitchCurve.startTangent = zero;
    lbl_803DD548->pitchCurve.endTangent = zero;
    ((CameraObject*)obj)->unk13E = 1;
    if (GameBit_Get(0xc64) != 0)
    {
        lbl_803DD548->flags.zoomHudEnabled = 1;
    }
    if (mode == 1)
    {
        lbl_803DD548->mode = VIEWFINDER_MODE_IDLE;
    }
    else
    {
        lbl_803DD548->mode = VIEWFINDER_MODE_ENTER_BLEND;
        lbl_803DD548->flags.sfxEnabled = 1;
        Sfx_PlayFromObject(0, lbl_803DD548->flags.zoomHudEnabled ? SFXTRIG_and_swipe2 : SFXTRIG_shop_priceup);
    }
    lbl_803DD548->flags.zoomSfxPlaying = 0;
    lbl_803DD548->clampedPosY = lbl_803DD548->camPosY;
}

void CameraModeViewfinder_release(void)
{
}

void CameraModeViewfinder_initialise(void)
{
}
