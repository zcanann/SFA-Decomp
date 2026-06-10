#include "main/dll/CAM/camshipbattle5C.h"
#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/camera_object.h"
#include "main/dll/CAM/camdebug_state.h"
#include "main/dll/CAM/camTalk.h"
#include "main/dll/CAM/camstatic_state.h"
#include "main/dll/rom_curve_interface.h"
#include "main/game_object.h"
#include "main/dll/CAM/viewfinder_state.h"
#include "main/dll/CAM/dll_5B.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/pad.h"


extern undefined4 FUN_800033a8();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern double FUN_800069f8();
extern int FUN_80006a10();
extern undefined4 FUN_80006a1c();
extern undefined4 FUN_80006a30();
extern undefined4 FUN_80006ba8();
extern char FUN_80006bb8();
extern char FUN_80006bc0();
extern char FUN_80006bc8();
extern char FUN_80006bd0();
extern uint FUN_80006c00();
extern uint FUN_80006c10();
extern u32 getButtonsHeld(int port);
extern char padGetCX(int port);
extern char padGetCY(int port);
extern double FUN_800176f4();
extern uint getAngle();
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017830();
extern int FUN_80017a98();
extern int ObjHits_GetPriorityHit();
extern void* ObjGroup_GetObjects();
extern undefined4 FUN_80053bf0();
extern undefined4 FUN_800810d8();
extern undefined4 camcontrol_applyState();
extern double fn_8010AEA8();
extern undefined4 FUN_80135814();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();
extern f32 sqrtf(f32 x);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern undefined4 FUN_80294c64();
extern undefined4 FUN_80294d00();

extern u8 framesThisStep;
extern ViewfinderState* lbl_803DD548;
extern CameraModeDebugState* lbl_803DD550;
extern CameraModeStaticState* lbl_803DD558;
extern f64 lbl_803E17D8;
extern f64 lbl_803E1838;
extern f64 lbl_803E1880;
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
extern f32 lbl_803E1814;
extern f32 lbl_803E1818;
extern f32 lbl_803E181C;
extern f32 lbl_803E1820;
extern f32 lbl_803E1824;
extern f32 lbl_803E1828;
extern f32 lbl_803E182C;
extern f32 lbl_803E1830;
extern f32 lbl_803E1840;
extern f32 lbl_803E1844;
extern f32 lbl_803E1848;
extern f32 lbl_803E184C;
extern f32 lbl_803E1850;
extern f32 lbl_803E1854;
extern f32 lbl_803E1858;
extern f32 lbl_803E185C;
extern f32 lbl_803E1860;
extern f32 lbl_803E1870;
extern f32 lbl_803E1878;
extern f32 lbl_803E1888;
extern f32 lbl_803E188C;


extern char padGetStickX(int port);
extern char padGetStickY(int port);
extern f32 interpolate(f32 v, f32 a, f32 b);
extern void fn_802961D4(short *obj, int v);
extern f32 Camera_GetFovY(void);
extern void viewFinderSetZoom(f32 fov);
extern void Sfx_StopFromObject(int obj, int sfxId);

/*
 * --INFO--
 *
 * Function: firstPersonDoControls
 * EN v1.0 Address: 0x8010847C
 * EN v1.0 Size: 1012b
 * EN v1.1 Address: 0x80108718
 * EN v1.1 Size: 1024b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void firstPersonDoControls(short *param_1)
{
  short sVar2;
  char cVar3;
  char cVar4;
  short *psVar5;
  int spinI;
  f32 t;
  f32 zoom;
  f32 spin;
  f32 fovTarget;
  f32 zoom2;

  psVar5 = *(short **)(param_1 + 0x52);
  cVar3 = padGetStickX(0);
  cVar4 = padGetStickY(0);
  t = (lbl_803E17E0 - *(f32 *)(param_1 + 0x5a)) / lbl_803E17E4;
  zoom = (t < lbl_803E17C4) ? lbl_803E17C4 : ((t > lbl_803E17E8) ? lbl_803E17E8 : t);
  spin = (f32)cVar3 * -(lbl_803E17F0 * zoom - lbl_803E17EC);
  spin = interpolate(spin - lbl_803DD548->yawSpeed, lbl_803E17F4, timeDelta);
  lbl_803DD548->yawSpeed = lbl_803DD548->yawSpeed + spin;
  if ((lbl_803DD548->yawSpeed > lbl_803E17F8) &&
     (lbl_803DD548->yawSpeed < lbl_803E17FC)) {
    lbl_803DD548->yawSpeed = lbl_803E17C4;
  }
  spinI = (int)(lbl_803E1800 * ((f32)cVar4 / lbl_803E1804));
  *param_1 = lbl_803DD548->yawSpeed * timeDelta + (f32)*param_1;
  sVar2 = spinI - (param_1[1] & 0xffffU);
  if (0x8000 < sVar2) {
    sVar2 = sVar2 - 0xffff;
  }
  if (sVar2 < -0x8000) {
    sVar2 = sVar2 + 0xffff;
  }
  spin = interpolate((f32)sVar2, lbl_803E17E8 / (lbl_803E180C * zoom + lbl_803E1808), timeDelta);
  param_1[1] = (f32)param_1[1] + spin;
  if (0x3c00 < param_1[1]) {
    param_1[1] = 0x3c00;
  }
  if (param_1[1] < -0x3c00) {
    param_1[1] = -0x3c00;
  }
  *psVar5 = 0x8000 - *param_1;
  if (psVar5[0x22] == 1) {
    fn_802961D4(psVar5, *psVar5);
  }
  if (lbl_803DD548->camPosY < lbl_803DD548->clampedPosY) {
    lbl_803DD548->clampedPosY = lbl_803DD548->camPosY;
  }
  *(f32 *)(param_1 + 0xc) = lbl_803DD548->camPosX;
  *(f32 *)(param_1 + 0xe) = lbl_803DD548->clampedPosY;
  *(f32 *)(param_1 + 0x10) = lbl_803DD548->camPosZ;
  if (lbl_803DD548->flags.zoomHudEnabled) {
    zoom2 = *(f32 *)(param_1 + 0x5a);
    cVar3 = padGetCY(0);
    t = (f32)-(int)cVar3;
    zoom2 = lbl_803E1810 * t * timeDelta + zoom2;
    viewFinderSetZoom(Camera_GetFovY());
    fovTarget = (zoom2 < lbl_803E17FC) ? lbl_803E17FC
                                        : ((zoom2 > lbl_803E17E0) ? lbl_803E17E0 : zoom2);
    if (lbl_803DD548->flags.sfxEnabled) {
      if ((fovTarget == *(f32 *)(param_1 + 0x5a)) &&
         (lbl_803DD548->flags.zoomSfxPlaying)) {
        Sfx_StopFromObject(0, 0x3d8);
        lbl_803DD548->flags.zoomSfxPlaying = 0;
      }
      if ((fovTarget != *(f32 *)(param_1 + 0x5a)) &&
         (!lbl_803DD548->flags.zoomSfxPlaying)) {
        Sfx_PlayFromObject(0, 0x3d8);
        lbl_803DD548->flags.zoomSfxPlaying = 1;
      }
    }
    *(f32 *)(param_1 + 0x5a) = fovTarget;
  }
}


/*
 * --INFO--
 *
 * Function: firstPersonEnter
 * EN v1.0 Address: 0x80108870
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80108B18
 * EN v1.1 Size: 596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int fn_802966D4(int obj, int *out);

int firstPersonEnter(u8 *cam, s16 *p2)
{
  f32 f2;
  u8 *state;
  int conv;
  int flag;
  int other;

  ((CameraObject *)cam)->anim.worldPosX = lbl_803DD548->camPosX;
  ((CameraObject *)cam)->anim.worldPosY = lbl_803DD548->camPosY;
  ((CameraObject *)cam)->anim.worldPosZ = lbl_803DD548->camPosZ;
  ((CameraObject *)cam)->anim.rotY = 0;
  flag = 0;
  if (((CameraObject *)cam)->unkF4 <= lbl_803E17C4) {
    flag = 1;
  }
  conv = (int)(lbl_803E1814 * ((CameraObject *)cam)->unkF4);
  state = ((CameraObject *)cam)->anim.targetObj;
  if (conv < 1) {
    conv = 1;
  }
  if (state != NULL) {
    state[54] = (u8)conv;
    if ((u8 *)Obj_GetPlayerObject() == state) {
      fn_802966D4((int)state, &other);
      if ((u32)other != 0) {
        *(u8 *)(other + 54) = (u8)conv;
        if (*(u8 *)(other + 54) == 1) {
          *(u8 *)(other + 54) = 0;
        }
      }
    }
  }
  if (flag != 0) {
    lbl_803DD548->viewCurve.px = &lbl_803DD548->yawCurve.start;
    lbl_803DD548->viewCurve.py = NULL;
    lbl_803DD548->viewCurve.pz = NULL;
    lbl_803DD548->viewCurve.count = 4;
    lbl_803DD548->viewCurve.eval = Curve_EvalHermite;
    lbl_803DD548->viewCurve.coeffFn = Curve_BuildHermiteCoeffs;
    lbl_803DD548->viewCurve.dir = 0;
    lbl_803DD548->yawCurve.start = (f32)(s32)*(s16 *)cam;
    lbl_803DD548->yawCurve.end = (f32)(s16)(0x8000 - p2[0]);
    f2 = lbl_803DD548->yawCurve.start - lbl_803DD548->yawCurve.end;
    if (f2 < lbl_803E1818 && f2 > lbl_803E181C) {
      lbl_803DD548->yawCurve.end = lbl_803DD548->yawCurve.start;
    } else if (f2 > lbl_803E17C8 || f2 < lbl_803E17CC) {
      if (lbl_803DD548->yawCurve.start < lbl_803E17C4) {
        lbl_803DD548->yawCurve.start += lbl_803E17D0;
      } else if (lbl_803DD548->yawCurve.end < lbl_803E17C4) {
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

/*
 * --INFO--
 *
 * Function: CameraModeViewfinder_copyToCurrent
 * EN v1.0 Address: 0x80108874
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x80108D6C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeViewfinder_copyToCurrent(undefined2 *param_1)
{
  u8 *src = (u8 *)param_1;
  u8 *cur;

  cur = (u8 *)(*gCameraInterface)->getCamera();
  if ((cur != NULL) && (src != NULL)) {
    *(s16 *)(cur + 0) = *(s16 *)(src + 0);
    *(s16 *)(cur + 2) = *(s16 *)(src + 2);
    *(s16 *)(cur + 4) = *(s16 *)(src + 4);
    *(f32 *)(cur + 12) = *(f32 *)(src + 8);
    *(f32 *)(cur + 16) = *(f32 *)(src + 12);
    *(f32 *)(cur + 20) = *(f32 *)(src + 16);
    *(f32 *)(cur + 24) = *(f32 *)(src + 8);
    *(f32 *)(cur + 28) = *(f32 *)(src + 12);
    *(f32 *)(cur + 32) = *(f32 *)(src + 16);
    *(f32 *)(cur + 180) = *(f32 *)(src + 20);
  }
}

/*
 * --INFO--
 *
 * Function: CameraModeViewfinder_free
 * EN v1.0 Address: 0x80108914
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x80108E08
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void Rcp_SetViewFinderHudEnabled(int on);
void CameraModeViewfinder_free(int param_1)
{
  int iVar1;
  int iVar2;
  int local_18 [5];

  *(ushort *)(*(int *)(param_1 + 0xa4) + 6) = *(ushort *)(*(int *)(param_1 + 0xa4) + 6) & ~0x4000;
  Rcp_SetViewFinderHudEnabled(0);
  iVar2 = *(int *)(param_1 + 0xa4);
  if (iVar2 != 0) {
    ((GameObject *)iVar2)->anim.alpha = 0xff;
    iVar1 = Obj_GetPlayerObject();
    if (iVar1 == iVar2) {
      fn_802966D4(iVar2,local_18);
      if (local_18[0] != 0) {
        ((GameObject *)local_18[0])->anim.alpha = 0xff;
        if (((GameObject *)local_18[0])->anim.alpha == 1) {
          ((GameObject *)local_18[0])->anim.alpha = 0;
        }
      }
    }
  }
  Sfx_StopFromObject(0,0x3d8);
  mm_free(lbl_803DD548);
  lbl_803DD548 = 0;
  viewFinderSetZoom((double)lbl_803E17E0);
  return;
}

extern void Rcp_SetViewFinderHudEnabled(int on);
extern void buttonDisable(int port, int mask);
extern void firstPersonZoomOutOnExit(int a, int b);
extern void fn_80137948(char *fmt, ...);
extern char sCam5BYDebugFormat;

/*
 * --INFO--
 *
 * Function: CameraModeViewfinder_update
 * EN v1.0 Address: 0x801089D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80108EC8
 * EN v1.1 Size: 1452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeViewfinder_update(s16 *param_1)
{
  u8 *targetObj;
  int brightness;
  int camObj;
  int angleDiff;
  f32 outA;
  f32 hitY;
  f32 outB;
  f32 hitDist;
  u8 *shadow2;
  u8 *shadow;

  camObj = *(int *)(param_1 + 0x52);
  getButtonsJustPressed(0);
  firstPersonPlaceCamera((GameObject *)camObj, 0);
  switch (lbl_803DD548->mode) {
  case 0:
    lbl_803DD548->mode = firstPersonEnter((u8 *)param_1, (s16 *)*(int *)(param_1 + 0x52));
    break;
  case 1:
    if (Curve_AdvanceAlongPath(&lbl_803DD548->viewCurve, lbl_803E1820) != 0) {
      if (lbl_803DD548->flags.zoomHudEnabled) {
        Rcp_SetViewFinderHudEnabled(1);
      }
      lbl_803DD548->mode = 2;
    }
    *param_1 = lbl_803DD548->viewCurve.sample[0];
    *(u8 *)(param_1 + 0x9f) = 1;
    break;
  case 2:
    if (lbl_803DD548->flags.zoomHudEnabled) {
      Rcp_SetViewFinderHudEnabled(1);
    }
    firstPersonDoControls((short *)param_1);
    if (getButtonsJustPressed(0) & 0x210) {
      buttonDisable(0, 0x200);
      firstPersonExit((CameraObject *)param_1);
      Rcp_SetViewFinderHudEnabled(0);
      lbl_803DD548->mode = 3;
    }
    *(u8 *)(param_1 + 0x9f) = 0;
    break;
  case 3:
    angleDiff = Curve_AdvanceAlongPath(&lbl_803DD548->viewCurve, lbl_803E1820);
    *param_1 = lbl_803DD548->viewCurve.sample[0];
    param_1[1] = lbl_803DD548->viewCurve.sample[1];
    if (angleDiff != 0) {
      lbl_803DD548->viewCurve.px = &lbl_803DD548->posXCurve.start;
      lbl_803DD548->viewCurve.py = &lbl_803DD548->posYCurve.start;
      lbl_803DD548->viewCurve.pz = &lbl_803DD548->posZCurve.start;
      lbl_803DD548->viewCurve.count = 4;
      lbl_803DD548->viewCurve.dir = 0;
      lbl_803DD548->viewCurve.eval = Curve_EvalHermite;
      lbl_803DD548->viewCurve.coeffFn = Curve_BuildHermiteCoeffs;
      curvesMove(&lbl_803DD548->viewCurve);
      *(s16 *)(*(int *)(param_1 + 0x52) + 6) = *(s16 *)(*(int *)(param_1 + 0x52) + 6) & ~0x4000;
      firstPersonZoomOutOnExit(0xf, 0xfe);
      lbl_803DD548->mode = 4;
      if (lbl_803DD548->flags.sfxEnabled) {
        Sfx_PlayFromObject(0, lbl_803DD548->flags.zoomHudEnabled ? 0x3f5 : 0x3f3);
      }
    }
    *(u8 *)(param_1 + 0x9f) = 1;
    break;
  case 4:
    *(f32 *)(param_1 + 0xc) = lbl_803DD548->posXCurve.end;
    *(f32 *)(param_1 + 0xe) = lbl_803DD548->posYCurve.end;
    *(f32 *)(param_1 + 0x10) = lbl_803DD548->posZCurve.end;
    {
      f32 fade = (lbl_803E17E8 - *(f32 *)(param_1 + 0x7a)) - lbl_803E1824;
      if (fade < lbl_803E17C4) {
        fade = lbl_803E17C4;
      }
      fade = fade * lbl_803E1828;
      if (fade > lbl_803E17E8) {
        fade = lbl_803E17E8;
      }
      brightness = (int)(lbl_803E1814 * fade);
    }
    targetObj = *(u8 **)(param_1 + 0x52);
    if (brightness < 1) {
      brightness = 1;
    }
    if (targetObj != NULL) {
      ((GameObject *)targetObj)->anim.alpha = brightness;
      if ((u8 *)Obj_GetPlayerObject() == targetObj) {
        fn_802966D4((int)targetObj, (int *)&shadow2);
        if (shadow2 != NULL) {
          ((GameObject *)shadow2)->anim.alpha = brightness;
          if (((GameObject *)shadow2)->anim.alpha == 1) {
            ((GameObject *)shadow2)->anim.alpha = 0;
          }
        }
      }
    }
    brightness = 0;
    if (*(f32 *)(param_1 + 0x7a) <= lbl_803E17C4) {
      brightness = 1;
    }
    (*gCameraInterface)->getRelativePosition(lbl_803E17C4, (int)param_1, &outA, &hitY,
                                             &outB, &hitDist, 0);
    if (hitDist < lbl_803E182C) {
      param_1[1] = 0;
    }
    else {
      hitY = *(f32 *)(param_1 + 0xe) - (*(f32 *)(camObj + 0x1c) + lbl_803E17C0);
      angleDiff = (getAngle() & 0xffff) - (param_1[1] & 0xffffU);
      if (angleDiff > 0x8000) {
        angleDiff = angleDiff - 0xffff;
      }
      if (angleDiff < -0x8000) {
        angleDiff = angleDiff + 0xffff;
      }
      param_1[1] = param_1[1] + (int)((f32)angleDiff * timeDelta) / 8;
    }
    if (brightness != 0) {
      (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
      targetObj = *(u8 **)(param_1 + 0x52);
      if (targetObj != NULL) {
        ((GameObject *)targetObj)->anim.alpha = 0xff;
        if ((u8 *)Obj_GetPlayerObject() == targetObj) {
          fn_802966D4((int)targetObj, (int *)&shadow);
          if (shadow != NULL) {
            ((GameObject *)shadow)->anim.alpha = 0xff;
            if (((GameObject *)shadow)->anim.alpha == 1) {
              ((GameObject *)shadow)->anim.alpha = 0;
            }
          }
        }
      }
    }
    *(u8 *)(param_1 + 0x9f) = 1;
    break;
  case 5:
    break;
  }
  if (ObjHits_GetPriorityHit(*(int *)(param_1 + 0x52), 0, 0, 0) != 0) {
    firstPersonExit((CameraObject *)param_1);
    *(f32 *)(param_1 + 0xc) = lbl_803DD548->posXCurve.end;
    *(f32 *)(param_1 + 0xe) = lbl_803DD548->posYCurve.end;
    *(f32 *)(param_1 + 0x10) = lbl_803DD548->posZCurve.end;
    (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0);
  }
  fn_80137948(&sCam5BYDebugFormat, *(f32 *)(param_1 + 0xe));
  Obj_TransformWorldPointToLocal(*(f32 *)(param_1 + 0xc), *(f32 *)(param_1 + 0xe), *(f32 *)(param_1 + 0x10),
                                 (f32 *)(param_1 + 6), (f32 *)(param_1 + 8), (f32 *)(param_1 + 10),
                                 *(int *)(param_1 + 0x18));
}

extern u32 GameBit_Get(int bit);
extern void *memset(void *dst, int v, int n);
extern f32 lbl_803E1834;
extern f64 lbl_803E1838x;

/*
 * --INFO--
 *
 * Function: CameraModeViewfinder_init
 * EN v1.0 Address: 0x801089D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80109474
 * EN v1.1 Size: 1396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeViewfinder_init(s16 *param_1, int param_2, int *param_3)
{
  s16 *camObj;
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

  camObj = *(s16 **)(param_1 + 0x52);
  if (lbl_803DD548 == NULL) {
    lbl_803DD548 = mmAlloc(0x134, 0xf, 0);
  }
  memset(lbl_803DD548, 0, 0x134);
  *(f32 *)lbl_803DD548 = *(f32 *)param_3;
  lbl_803DD548->unk114 = (f32)(u32)*(u16 *)((int)param_3 + 8);
  lbl_803DD548->unk4 = *(f32 *)(param_3 + 1);
  lbl_803DD548->yawSpeed = lbl_803E17C4;
  diff = 0x8000 - param_1[0] - camObj[0];
  if (diff < 0) {
    absDiff = -diff;
  }
  else {
    absDiff = diff;
  }
  spinRate = (f32)diff / lbl_803E17E4;
  rollRate = (f32)absDiff / lbl_803E1830;
  lbl_803DD548->viewCurve.px = &lbl_803DD548->posXCurve.start;
  lbl_803DD548->viewCurve.py = &lbl_803DD548->posYCurve.start;
  lbl_803DD548->viewCurve.pz = &lbl_803DD548->posZCurve.start;
  lbl_803DD548->viewCurve.count = 4;
  lbl_803DD548->viewCurve.dir = 0;
  lbl_803DD548->viewCurve.eval = Curve_EvalHermite;
  lbl_803DD548->viewCurve.coeffFn = Curve_BuildHermiteCoeffs;
  dx = *(f32 *)(param_1 + 0xc) - *(f32 *)(camObj + 0xc);
  dz = *(f32 *)(param_1 + 0x10) - *(f32 *)(camObj + 0x10);
  dist = sqrtf(dx * dx + dz * dz);
  if (lbl_803E17C4 != dist) {
    dx = dx / dist;
    dz = dz / dist;
  }
  firstPersonPlaceCamera((GameObject *)camObj, 1);
  cosv = -mathSinf((lbl_803E1834 * (f32)camObj[0]) / lbl_803E17C8);
  sinv = -mathCosf((lbl_803E1834 * (f32)camObj[0]) / lbl_803E17C8);
  lbl_803DD548->posXCurve.start = *(f32 *)(param_1 + 0xc);
  lbl_803DD548->posXCurve.end = lbl_803DD548->camPosX;
  lbl_803DD548->posXCurve.startTangent = -dz * spinRate;
  lbl_803DD548->posXCurve.endTangent = cosv * rollRate;
  lbl_803DD548->posYCurve.start = *(f32 *)(param_1 + 0xe);
  lbl_803DD548->posYCurve.end = lbl_803DD548->camPosY;
  zero = lbl_803E17C4;
  lbl_803DD548->posYCurve.startTangent = zero;
  lbl_803DD548->posYCurve.endTangent = zero;
  lbl_803DD548->posZCurve.start = *(f32 *)(param_1 + 0x10);
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
  a2 = param_1[0] - (u16)(0x8000 - getAngle(*(f32 *)(param_1 + 0xc) - lbl_803DD548->posXCurve.end,
                                            *(f32 *)(param_1 + 0x10) - lbl_803DD548->posZCurve.end));
  if (a2 > 0x8000) {
    a2 = a2 - 0xffff;
  }
  if (a2 < -0x8000) {
    a2 = a2 + 0xffff;
  }
  lbl_803DD548->yawCurve.start = (f32)a2;
  lbl_803DD548->yawCurve.end = lbl_803E17C4;
  lbl_803DD548->yawCurve.startTangent = lbl_803E17C4;
  lbl_803DD548->yawCurve.endTangent = lbl_803E17C4;
  dx = lbl_803DD548->yawCurve.start - lbl_803DD548->yawCurve.end;
  if (dx > lbl_803E17C8 || dx < lbl_803E17CC) {
    if (lbl_803DD548->yawCurve.start < lbl_803E17C4) {
      lbl_803DD548->yawCurve.start = lbl_803DD548->yawCurve.start + lbl_803E17D0;
    }
    else if (lbl_803DD548->yawCurve.end < lbl_803E17C4) {
      lbl_803DD548->yawCurve.end = lbl_803DD548->yawCurve.end + lbl_803E17D0;
    }
  }
  lbl_803DD548->pitchCurve.start = (f32)param_1[1];
  lbl_803DD548->pitchCurve.end = lbl_803E17C4;
  lbl_803DD548->pitchCurve.startTangent = lbl_803E17C4;
  lbl_803DD548->pitchCurve.endTangent = lbl_803E17C4;
  *(u8 *)(param_1 + 0x9f) = 1;
  if (GameBit_Get(0xc64) != 0) {
    lbl_803DD548->flags.zoomHudEnabled = 1;
  }
  if (param_2 == 1) {
    lbl_803DD548->mode = 5;
  }
  else {
    lbl_803DD548->mode = 0;
    lbl_803DD548->flags.sfxEnabled = 1;
    Sfx_PlayFromObject(0, lbl_803DD548->flags.zoomHudEnabled ? 0x3f4 : 0x28b);
  }
  lbl_803DD548->flags.zoomSfxPlaying = 0;
  lbl_803DD548->clampedPosY = lbl_803DD548->camPosY;
}

/*
 * --INFO--
 *
 * Function: FUN_801089d8
 * EN v1.0 Address: 0x801089D8
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x801099E8
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801089d8(void)
{
  FUN_80017814(lbl_803DD550);
  lbl_803DD550 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: CameraModeDebug_update
 * EN v1.0 Address: 0x80108A04
 * EN v1.0 Size: 848b
 * EN v1.1 Address: 0x80109A14
 * EN v1.1 Size: 816b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeDebug_update(short *param_1)
{
  u8 *cam = (u8 *)param_1;
  u8 *state = *(u8 **)(cam + 164);
  u16 held;
  f32 move;
  f32 absMove;
  f32 absVel;
  f32 factor;
  f32 radius;

  if ((getButtonsJustPressed(0) & 2) != 0) {
    (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
    return;
  }
  move = lbl_803E1840;
  held = getButtonsHeld(0);
  if ((held & 8) != 0) {
    move = lbl_803E1844 * lbl_803DD550->orbitRadius;
  }
  if ((held & 4) != 0) {
    move = lbl_803E1848 * lbl_803DD550->orbitRadius;
  }
  absMove = (move < lbl_803E1840) ? -move : move;
  absVel = (lbl_803DD550->radiusVelocity < lbl_803E1840) ? -lbl_803DD550->radiusVelocity : lbl_803DD550->radiusVelocity;
  factor = lbl_803E1850;
  if (absMove < absVel) {
    factor = lbl_803E184C;
  }
  lbl_803DD550->radiusVelocity = factor * (move - lbl_803DD550->radiusVelocity) + lbl_803DD550->radiusVelocity;
  lbl_803DD550->orbitRadius = lbl_803DD550->orbitRadius + lbl_803DD550->radiusVelocity;
  if (lbl_803DD550->orbitRadius < lbl_803E1854) {
    lbl_803DD550->orbitRadius = lbl_803E1854;
  }
  if (lbl_803DD550->orbitRadius > lbl_803E1858) {
    lbl_803DD550->orbitRadius = lbl_803E1858;
  }
  *(s16 *)cam = (s16)(*(s16 *)cam - (s8)padGetCX(0) * 3);
  *(s16 *)(cam + 2) = (s16)(*(s16 *)(cam + 2) + (s8)padGetCY(0) * 3);
  {
    f32 cosYaw = mathSinf(lbl_803E185C * (f32)(s32)(*(s16 *)cam - 0x4000) / lbl_803E1860);
    f32 sinYaw = mathCosf(lbl_803E185C * (f32)(s32)(*(s16 *)cam - 0x4000) / lbl_803E1860);
    f32 sinPitch = mathCosf(lbl_803E185C * (f32)(s32)(*(s16 *)(cam + 2) - 0x4000) / lbl_803E1860);
    f32 cosPitch = mathSinf(lbl_803E185C * (f32)(s32)(*(s16 *)(cam + 2) - 0x4000) / lbl_803E1860);
    radius = lbl_803DD550->orbitRadius;
    *(f32 *)(cam + 24) = *(f32 *)(state + 24) + radius * sinPitch * sinYaw;
    *(f32 *)(cam + 28) = lbl_803E1854 + *(f32 *)(state + 28) + radius * cosPitch;
    *(f32 *)(cam + 32) = *(f32 *)(state + 32) + radius * sinPitch * cosYaw;
  }
  Obj_TransformWorldPointToLocal(*(f32 *)(cam + 24), *(f32 *)(cam + 28), *(f32 *)(cam + 32),
                                 (f32 *)(cam + 12), (f32 *)(cam + 16), (f32 *)(cam + 20),
                                 *(int *)(cam + 48));
}

/*
 * --INFO--
 *
 * Function: CameraModeDebug_init
 * EN v1.0 Address: 0x80108D54
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80109D44
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeDebug_init(void)
{
  if (lbl_803DD550 == NULL) {
    lbl_803DD550 = (CameraModeDebugState *)mmAlloc(sizeof(CameraModeDebugState),0xf,0);
  }
  lbl_803DD550->orbitRadius = lbl_803E1870;
  lbl_803DD550->radiusVelocity = lbl_803E1840;
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80109B04
 * EN v1.0 Address: 0x80108D58
 * EN v1.0 Size: 292b
 * EN v1.1 Address: 0x80109DA0
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
void *fn_80109B04(f32 x, f32 y, f32 z, int filter1, int filter2)
{
    int *list;
    int i;
    void *best;
    double bestDist;
    int count;
    int *obj;
    int *tmpList;
    f32 dx, dy, dz;
    f32 yy;
    double dist;

    bestDist = lbl_803E1878;
    best = NULL;
    tmpList = (int *)ObjGroup_GetObjects(7, &count);
    for (i = 0, list = tmpList; i < count; i++) {
        obj = (int *)*list;
        if (((GameObject *)obj)->anim.classId == filter2 &&
            *(u8 *)(*(int *)&((GameObject *)obj)->anim.placementData + 0x18) == filter1) {
            dx = x - ((GameObject *)obj)->anim.worldPosX;
            dy = y - ((GameObject *)obj)->anim.worldPosY;
            dz = z - ((GameObject *)obj)->anim.worldPosZ;
            yy = dy*dy;
            dist = sqrtf(yy + dx*dx + dz*dz);
            if (dist < bestDist) {
                bestDist = dist;
                best = obj;
            }
        }
        list++;
    }
    return best;
}
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: FUN_80108e7c
 * EN v1.0 Address: 0x80108E7C
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80109EB4
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80108e7c(void)
{
  FUN_80017814(lbl_803DD558);
  lbl_803DD558 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: CameraModeStatic_update
 * EN v1.0 Address: 0x80108EA8
 * EN v1.0 Size: 608b
 * EN v1.1 Address: 0x80109EE0
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeStatic_update(short *param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  if (lbl_803DD558->missingObject != 0) {
    (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
  }
  else {
    iVar3 = *(int *)(param_1 + 0x52);
    iVar4 = (int)lbl_803DD558->staticObject->anim.placementData;
    if ((*(byte *)(iVar4 + 0x1b) & 1) == 0) {
      *param_1 = *(short *)(iVar4 + 0x1c) + -0x8000;
    }
    if ((*(byte *)(iVar4 + 0x1b) & 2) == 0) {
      param_1[1] = *(short *)(iVar4 + 0x1e);
    }
    if ((*(byte *)(iVar4 + 0x1b) & 4) == 0) {
      param_1[2] = *(short *)(iVar4 + 0x20);
    }
    ((CameraObject *)param_1)->anim.worldPosX = lbl_803DD558->staticObject->anim.worldPosX;
    ((CameraObject *)param_1)->anim.worldPosY = lbl_803DD558->staticObject->anim.worldPosY;
    ((CameraObject *)param_1)->anim.worldPosZ = lbl_803DD558->staticObject->anim.worldPosZ;
    *(float *)(param_1 + 0x5a) = (float)(uint)*(byte *)(iVar4 + 0x1a);
    dVar6 = (double)(*(float *)(param_1 + 0xc) - *(float *)(iVar3 + 0x18));
    dVar7 = (double)(*(float *)(param_1 + 0xe) - *(float *)(iVar3 + 0x1c));
    dVar5 = (double)(*(float *)(param_1 + 0x10) - *(float *)(iVar3 + 0x20));
    if ((*(byte *)(iVar4 + 0x1b) & 1) != 0) {
      iVar1 = getAngle(dVar6,dVar5);
      *param_1 = -0x8000 - (short)iVar1;
    }
    if ((*(byte *)(iVar4 + 0x1b) & 2) != 0) {
      uVar2 = getAngle(dVar7,sqrtf((float)(dVar6 * dVar6 + (double)(float)(dVar5 * dVar5))));
      iVar1 = ((uVar2 & 0xffff) - (int)*(short *)(iVar4 + 0x1e)) - (uint)(ushort)param_1[1];
      if (0x8000 < iVar1) {
        iVar1 = iVar1 + -0xffff;
      }
      if (iVar1 < -0x8000) {
        iVar1 = iVar1 + 0xffff;
      }
      param_1[1] = param_1[1] + (short)((int)(iVar1 * (uint)framesThisStep) >> 3);
    }
    if ((*(byte *)(iVar4 + 0x1b) & 4) != 0) {
      iVar3 = (int)param_1[2] - (uint)*(ushort *)(iVar3 + 4);
      if (0x8000 < iVar3) {
        iVar3 = iVar3 + -0xffff;
      }
      if (iVar3 < -0x8000) {
        iVar3 = iVar3 + 0xffff;
      }
      param_1[2] = param_1[2] + (short)((int)(iVar3 * (uint)framesThisStep) >> 3);
    }
    Obj_TransformWorldPointToLocal(*(float *)(param_1 + 0xc),*(float *)(param_1 + 0xe),
                 *(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: CameraModeStatic_init
 * EN v1.0 Address: 0x80109108
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010A198
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeStatic_init(u8 *cam, int p2, int *p3)
{
  GameObject *state;
  GameObject *best;
  u8 *setup;
  s16 yaw;
  int pitch;
  s16 roll;
  f32 dx;
  f32 dy;
  f32 dz;

  state = ((CameraObject *)cam)->anim.targetObj;
  if (lbl_803DD558 == NULL) {
    lbl_803DD558 = (CameraModeStaticState *)mmAlloc(sizeof(CameraModeStaticState), 15, 0);
  }
  lbl_803DD558->active = 1;
  lbl_803DD558->missingObject = 0;
  best = (GameObject *)fn_80109B04(state->anim.worldPosX, state->anim.worldPosY, state->anim.worldPosZ, *p3, 18);
  if (best == NULL) {
    lbl_803DD558->missingObject = 1;
    return;
  }
  lbl_803DD558->staticObject = best;
  setup = (u8 *)best->anim.placementData;
  dx = best->anim.worldPosX - state->anim.worldPosX;
  dy = best->anim.worldPosY - state->anim.worldPosY;
  dz = best->anim.worldPosZ - state->anim.worldPosZ;
  if ((setup[27] & 1) != 0) {
    yaw = 0x8000 - getAngle(dx, dz);
  } else {
    yaw = *(s16 *)(setup + 28) + 0x8000;
  }
  if ((setup[27] & 2) != 0) {
    pitch = (s16)getAngle(dy, sqrtf(dx * dx + dz * dz)) - *(s16 *)(setup + 30);
  } else {
    pitch = *(s16 *)(setup + 30);
  }
  if ((setup[27] & 4) != 0) {
    roll = state->anim.rotZ;
  } else {
    roll = *(s16 *)(setup + 32);
  }
  {
    f32 fov = (f32)(u32)setup[26];
    ((CameraObject *)cam)->anim.worldPosX = best->anim.worldPosX;
    ((CameraObject *)cam)->anim.worldPosY = best->anim.worldPosY;
    ((CameraObject *)cam)->anim.worldPosZ = best->anim.worldPosZ;
    ((CameraObject *)cam)->anim.rotX = yaw;
    ((CameraObject *)cam)->anim.rotY = pitch;
    ((CameraObject *)cam)->anim.rotZ = roll;
    ((CameraObject *)cam)->fov = fov;
  }
  Obj_TransformWorldPointToLocal(((CameraObject *)cam)->anim.worldPosX, ((CameraObject *)cam)->anim.worldPosY, ((CameraObject *)cam)->anim.worldPosZ,
                                 (f32 *)(cam + 12), (f32 *)(cam + 16), (f32 *)(cam + 20),
                                 *(int *)&((CameraObject *)cam)->anim.parent);
}



/*
 * --INFO--
 *
 * Function: fn_8010A104
 * EN v1.0 Address: 0x8010910C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010A3A0
 * EN v1.1 Size: 888b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8010A104(int *p1, int *p2, f32 x, f32 y, f32 z, int tag)
{
  int curve;
  int linked;
  int i;
  int k;
  int window[4];
  int count;
  int dummy;
  int found;
  int done;
  f32 dist;

  curve = (int)(*gRomCurveInterface)->getById(*p1);
  found = 1;
  for (i = 0; i < 5; i++) {
    if (*(int *)(curve + 28 + i * 4) > -1 &&
        ((s8)*(s8 *)(curve + 27) & (1 << i)) == 0) {
      linked = (int)(*gRomCurveInterface)->getById(*(int *)(curve + 28 + i * 4));
      if (linked != 0 &&
          (*(u8 *)(linked + 49) == tag || *(u8 *)(linked + 50) == tag ||
           *(u8 *)(linked + 51) == tag)) {
        found = 0;
        i = 5;
      }
    }
  }
  if (found != 0) {
    for (i = 0; i < 5; i++) {
      if (*(int *)(curve + 28 + i * 4) > -1 &&
          ((s8)*(s8 *)(curve + 27) & (1 << i)) != 0) {
        linked = (int)(*gRomCurveInterface)->getById(*(int *)(curve + 28 + i * 4));
        if (linked != 0 &&
            (*(u8 *)(linked + 49) == tag || *(u8 *)(linked + 50) == tag ||
             *(u8 *)(linked + 51) == tag)) {
          *p1 = *(int *)(curve + 28 + i * 4);
          i = 5;
        }
      }
    }
  }
  done = 0;
  do {
    done = 1;
    curve = (int)(*gRomCurveInterface)->getById(*p1);
    pathcam_findTaggedNodeWindow((u8 *)curve, window, tag);
    dist = fn_8010AC48(window, x, y, z);
    if (dist < lbl_803E1888) {
      if (window[0] > -1) {
        *p1 = window[0];
        done = 0;
      }
    } else if (dist > lbl_803E188C) {
      if (window[2] > -1 && window[3] > -1) {
        *p1 = window[2];
        done = 0;
      }
    }
  } while (done == 0);
  curve = (int)(*gRomCurveInterface)->getById(*p1);
  fn_8010A47C(curve, &count, tag);
  curve = (int)(*gRomCurveInterface)->getById(*p2);
  *p2 = *(int *)(fn_8010A47C(curve, &dummy, tag) + 20);
  for (k = 0; k < count; k++) {
    curve = (int)(*gRomCurveInterface)->getById(*p2);
    for (i = 0; i < 5; i++) {
      if (*(int *)(curve + 28 + i * 4) > -1 &&
          ((s8)*(s8 *)(curve + 27) & (1 << i)) == 0) {
        linked = (int)(*gRomCurveInterface)->getById(*(int *)(curve + 28 + i * 4));
        if (linked != 0 &&
            (*(u8 *)(linked + 49) == tag || *(u8 *)(linked + 50) == tag ||
             *(u8 *)(linked + 51) == tag)) {
          *p2 = *(int *)(curve + 28 + i * 4);
          i = 5;
        }
      }
    }
  }
}

/*
 * --INFO--
 *
 * Function: fn_8010A47C
 * EN v1.0 Address: 0x80109110
 * EN v1.0 Size: 280b
 * EN v1.1 Address: 0x8010A718
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fn_8010A47C(int curve, int *count, int tag)
{
  int i;
  int done;
  int linked;
  
  done = 0;
  *count = 0;
  while (done == 0) {
    done = 1;
    if ((*(char *)(curve + 0x19) != '\x1b') && (*(char *)(curve + 0x19) != '\x1a')) {
      for (i = 0; i < 5; i = i + 1) {
        if ((*(int *)(curve + i * 4 + 0x1c) > -1) &&
            (((int)*(char *)(curve + 0x1b) & (1 << i)) != 0)) {
          linked = (int)(*gRomCurveInterface)->getById(*(int *)(curve + i * 4 + 0x1c));
          if (((u32)linked != 0) &&
              ((*(u8 *)(linked + 0x31) == tag || (*(u8 *)(linked + 0x32) == tag)) ||
               (*(u8 *)(linked + 0x33) == tag))) {
            curve = linked;
            done = 0;
            i = 5;
          }
        }
      }
    }
    if (done == 0) {
      *count = *count + 1;
    }
  }
  return curve;
}


/* Trivial 4b 0-arg blr leaves. */
void CameraModeViewfinder_release(void) {}
void CameraModeViewfinder_initialise(void) {}
void CameraModeDebug_copyToCurrent_nop(void) {}
void CameraModeDebug_release_nop(void) {}
void CameraModeDebug_initialise_nop(void) {}
void CameraModeStatic_copyToCurrent_nop(void) {}
void CameraModeStatic_release(void) {}
void CameraModeStatic_initialise(void) {}

/* fn_X(lbl); lbl = 0; */
void CameraModeDebug_free(void) { mm_free(lbl_803DD550); lbl_803DD550 = 0; }
void CameraModeStatic_free(void) { mm_free(lbl_803DD558); lbl_803DD558 = 0; }
