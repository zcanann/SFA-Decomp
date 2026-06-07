#include "main/dll/CAM/dll_5F.h"
#include "main/camera_object.h"
#include "main/game_object.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/pad.h"


#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_800033a8();
extern f32 Curve_EvalCatmullRom(f32 *samples, f32 t, f32 *out);
extern f32 Curve_EvalBSpline(f32 *samples, f32 t, f32 *out);
extern int FUN_80017730();
extern undefined4 FUN_80017830();
extern undefined4 fn_8010A104();
extern void pathcam_buildWindowSamples(int *window, f32 *x, f32 *y, f32 *z, f32 *pitch, f32 *yaw, f32 *roll, f32 *fov);
extern void pathcam_findTaggedNodeWindow(int node, int *window, int p3);
extern f32 fn_8010AC48(f32 x, f32 y, f32 z, int *window);
extern int fn_8010AEA8(short *cam, int flags);
extern int getAngle(f32 a, f32 b);
typedef int (*RomCurveGetNodeFn)(int);
typedef void (*CameraRequestFn)(int, int, int, int, int, int, int);
extern undefined4 FUN_8010b218();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();
extern f32 sqrtf(f32);
extern void cameraModeTestStrengthFn_8010b238(int camera, f32 *pos, s16 pitch, s16 yaw, s16 roll);
extern void *memset(void *p, int c, int n);
typedef int (*RomCurveFindFn)(f32 x, f32 y, f32 z, int *tags, int count, int map);

extern u8 framesThisStep;
extern int *gCameraInterface;
extern undefined4* gRomCurveInterface;
extern undefined4* lbl_803DD560;
extern f64 lbl_803E18A0;
extern f32 lbl_803E1888;
extern f32 lbl_803E188C;
extern f32 lbl_803E18BC;

/*
 * --INFO--
 *
 * Function: CameraModeTestStrength_update
 * EN v1.0 Address: 0x8010B424
 * EN v1.0 Size: 2392b
 * EN v1.1 Address: 0x8010B6C0
 * EN v1.1 Size: 1652b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeTestStrength_update(short *cam)
{
  int m4;
  int obj;
  int m2;
  int node;
  int m1;
  int flags;
  int yaw;
  f32 t;
  f32 dx;
  f32 dy;
  f32 dz;
  f32 t2;
  int node2;
  int w2[4];
  int w1[4];
  f32 x[4];
  f32 y[4];
  f32 z[4];
  f32 pitchS[4];
  f32 yawS[4];
  f32 rollS[4];
  f32 fov[4];

  if (*((u8 *)lbl_803DD560 + 0x65) != 0) {
    (*(CameraRequestFn *)(*(int *)gCameraInterface + 0x1c))(0x42, 0, 1, 0, 0, 0, 0xff);
  } else {
    obj = *(int *)((char *)cam + 0xa4);
    getButtonsJustPressed(0);
    node = (*(RomCurveGetNodeFn *)(*(int *)gRomCurveInterface + 0x1c))(lbl_803DD560[3]);
    node2 = (*(RomCurveGetNodeFn *)(*(int *)gRomCurveInterface + 0x1c))(lbl_803DD560[2]);
    pathcam_findTaggedNodeWindow(node2, w1, lbl_803DD560[1]);
    pathcam_findTaggedNodeWindow(node, w2, lbl_803DD560[1]);
    pathcam_buildWindowSamples(w1, x, y, z, pitchS, yawS, rollS, fov);
    t2 = fn_8010AC48(((GameObject *)obj)->anim.worldPosX, ((GameObject *)obj)->anim.worldPosY, ((GameObject *)obj)->anim.worldPosZ, w2);
    if (t2 < lbl_803E1888) {
      if (w2[0] > -1) {
        lbl_803DD560[3] = w2[0];
        node2 = (*(RomCurveGetNodeFn *)(*(int *)gRomCurveInterface + 0x1c))(lbl_803DD560[3]);
        pathcam_findTaggedNodeWindow(node2, w2, lbl_803DD560[1]);
        if (w1[0] > -1) {
          lbl_803DD560[2] = w1[0];
          node2 = (*(RomCurveGetNodeFn *)(*(int *)gRomCurveInterface + 0x1c))(lbl_803DD560[2]);
          pathcam_findTaggedNodeWindow(node2, w1, lbl_803DD560[1]);
          pathcam_buildWindowSamples(w1, x, y, z, pitchS, yawS, rollS, fov);
          t2 = fn_8010AC48(((GameObject *)obj)->anim.worldPosX, ((GameObject *)obj)->anim.worldPosY, ((GameObject *)obj)->anim.worldPosZ, w2);
          *(f32 *)((char *)lbl_803DD560 + 0x58) += lbl_803E188C;
        } else {
          t2 = lbl_803E1888;
        }
      } else {
        t2 = lbl_803E1888;
      }
    } else if (t2 > lbl_803E188C) {
      if (w2[2] > -1 && w2[3] > -1) {
        lbl_803DD560[3] = w2[2];
        node2 = (*(RomCurveGetNodeFn *)(*(int *)gRomCurveInterface + 0x1c))(lbl_803DD560[3]);
        pathcam_findTaggedNodeWindow(node2, w2, lbl_803DD560[1]);
        if (w1[2] > -1 && w1[3] > -1) {
          lbl_803DD560[2] = w1[2];
          node2 = (*(RomCurveGetNodeFn *)(*(int *)gRomCurveInterface + 0x1c))(lbl_803DD560[2]);
          pathcam_findTaggedNodeWindow(node2, w1, lbl_803DD560[1]);
          pathcam_buildWindowSamples(w1, x, y, z, pitchS, yawS, rollS, fov);
          t2 = fn_8010AC48(((GameObject *)obj)->anim.worldPosX, ((GameObject *)obj)->anim.worldPosY, ((GameObject *)obj)->anim.worldPosZ, w2);
          *(f32 *)((char *)lbl_803DD560 + 0x58) -= lbl_803E188C;
        } else {
          t2 = lbl_803E188C;
        }
      } else {
        t2 = lbl_803E188C;
      }
    }
    t = lbl_803E18BC * (t2 - *(f32 *)((char *)lbl_803DD560 + 0x58)) +
        *(f32 *)((char *)lbl_803DD560 + 0x58);
    *(f32 *)((char *)lbl_803DD560 + 0x58) = t;
    ((CameraObject *)cam)->anim.worldPosX = Curve_EvalBSpline(x, t, (f32 *)0);
    ((CameraObject *)cam)->anim.worldPosY = Curve_EvalBSpline(y, t, (f32 *)0);
    ((CameraObject *)cam)->anim.worldPosZ = Curve_EvalBSpline(z, t, (f32 *)0);
    node2 = (*(RomCurveGetNodeFn *)(*(int *)gRomCurveInterface + 0x1c))(lbl_803DD560[2]);
    flags = *(u8 *)(node2 + 0x3b);
    m1 = flags & 1;
    if (m1 == 0) {
      *cam = (int)Curve_EvalCatmullRom(pitchS, t, (f32 *)0) + 0x8000;
    }
    m2 = flags & 2;
    if (m2 == 0) {
      cam[1] = Curve_EvalCatmullRom(yawS, t, (f32 *)0);
    }
    m4 = flags & 4;
    if (m4 == 0) {
      cam[2] = Curve_EvalCatmullRom(rollS, t, (f32 *)0);
    }
    ((CameraObject *)cam)->fov = Curve_EvalBSpline(fov, t, (f32 *)0);
    if (*((u8 *)lbl_803DD560 + 0x64) == 0 && fn_8010AEA8(cam, flags) != 0) {
      *((u8 *)lbl_803DD560 + 0x64) = 1;
    }
    dx = ((CameraObject *)cam)->anim.worldPosX - ((GameObject *)obj)->anim.worldPosX;
    dy = ((CameraObject *)cam)->anim.worldPosY - ((GameObject *)obj)->anim.worldPosY;
    dz = ((CameraObject *)cam)->anim.worldPosZ - ((GameObject *)obj)->anim.worldPosZ;
    if (m1 != 0) {
      *cam = 0x8000 - getAngle(dx, dz);
    }
    if (m2 != 0) {
      int d;
      yaw = (u16)getAngle(dy, sqrtf(dx * dx + dz * dz));
      d = (int)(((f32)yaw - Curve_EvalCatmullRom(yawS, t, (f32 *)0)) -
                    (f32)(cam[1] & 0xffff));
      if (d > 0x8000) {
        d -= 0xffff;
      }
      if (d < -0x8000) {
        d += 0xffff;
      }
      cam[1] = cam[1] + ((int)(d * (u32)framesThisStep) >> 3);
    }
    if (m4 != 0) {
      int d = cam[2] - (((GameObject *)obj)->anim.rotZ & 0xffff);
      if (d > 0x8000) {
        d -= 0xffff;
      }
      if (d < -0x8000) {
        d += 0xffff;
      }
      cam[2] = cam[2] + ((int)(d * (u32)framesThisStep) >> 3);
    }
    if (*(void **)lbl_803DD560 != (void *)0) {
      f32 v;
      v = ((CameraObject *)cam)->anim.worldPosX;
      *(f32 *)(*(int *)lbl_803DD560 + 0x18) = v;
      *(f32 *)(*(int *)lbl_803DD560 + 0xc) = v;
      v = ((CameraObject *)cam)->anim.worldPosY;
      *(f32 *)(*(int *)lbl_803DD560 + 0x1c) = v;
      *(f32 *)(*(int *)lbl_803DD560 + 0x10) = v;
      v = ((CameraObject *)cam)->anim.worldPosZ;
      *(f32 *)(*(int *)lbl_803DD560 + 0x20) = v;
      *(f32 *)(*(int *)lbl_803DD560 + 0x14) = v;
    }
    Obj_TransformWorldPointToLocal(((CameraObject *)cam)->anim.worldPosX, ((CameraObject *)cam)->anim.worldPosY,
                                   ((CameraObject *)cam)->anim.worldPosZ, (float *)(cam + 6),
                                   (float *)(cam + 8), (float *)(cam + 10), *(int *)(cam + 0x18));
  }
}

/*
 * --INFO--
 *
 * Function: CameraModeTestStrength_init
 * EN v1.0 Address: 0x8010BD7C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010BD34
 * EN v1.1 Size: 1128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeTestStrength_init(short *cam, int param2, int *param3)
{
  int romNode;
  int obj;
  int curveNode2;
  int pitch;
  int yaw;
  int roll;
  f32 t;
  f32 px;
  f32 py;
  f32 pz;
  f32 dx;
  f32 dy;
  f32 dz;
  f32 fov;
  f32 pos[3];
  int nextW[4];
  int prevW[4];
  f32 pitchS[4];
  f32 yawS[4];
  f32 rollS[4];
  f32 fovS[4];
  f32 xS[4];
  f32 yS[4];
  f32 zS[4];
  int tags[2];

  obj = *(int *)((char *)cam + 0xa4);
  if (lbl_803DD560 == 0) {
    lbl_803DD560 = mmAlloc(0x68, 0xf, 0);
  }
  memset(lbl_803DD560, 0, 0x68);
  lbl_803DD560[1] = *param3;
  *((u8 *)lbl_803DD560 + 0x64) = 1;
  tags[0] = 9;
  tags[1] = 0x1b;
  lbl_803DD560[3] = (*(RomCurveFindFn *)(*(int *)gRomCurveInterface + 0x14))(
      ((GameObject *)obj)->anim.worldPosX, ((GameObject *)obj)->anim.worldPosY, ((GameObject *)obj)->anim.worldPosZ, tags, 2, lbl_803DD560[1]);
  tags[0] = 8;
  tags[1] = 0x1a;
  lbl_803DD560[2] = (*(RomCurveFindFn *)(*(int *)gRomCurveInterface + 0x14))(
      ((GameObject *)obj)->anim.worldPosX, ((GameObject *)obj)->anim.worldPosY, ((GameObject *)obj)->anim.worldPosZ, tags, 2, lbl_803DD560[1]);
  fn_8010A104((int *)&lbl_803DD560[3], (int *)&lbl_803DD560[2], ((GameObject *)obj)->anim.worldPosX,
              ((GameObject *)obj)->anim.worldPosY, ((GameObject *)obj)->anim.worldPosZ, lbl_803DD560[1]);
  romNode = (*(RomCurveGetNodeFn *)(*(int *)gRomCurveInterface + 0x1c))(lbl_803DD560[2]);
  curveNode2 = (*(RomCurveGetNodeFn *)(*(int *)gRomCurveInterface + 0x1c))(lbl_803DD560[3]);
  pathcam_findTaggedNodeWindow(romNode, prevW, lbl_803DD560[1]);
  pathcam_findTaggedNodeWindow(curveNode2, nextW, lbl_803DD560[1]);
  pathcam_buildWindowSamples(prevW, xS, yS, zS, pitchS, yawS, rollS, fovS);
  t = fn_8010AC48(((GameObject *)obj)->anim.worldPosX, ((GameObject *)obj)->anim.worldPosY, ((GameObject *)obj)->anim.worldPosZ, nextW);
  if (t < lbl_803E1888) {
    t = lbl_803E1888;
  } else if (t > lbl_803E188C) {
    t = lbl_803E188C;
  }
  px = Curve_EvalBSpline(xS, t, (f32 *)0);
  py = Curve_EvalBSpline(yS, t, (f32 *)0);
  pz = Curve_EvalBSpline(zS, t, (f32 *)0);
  dx = px - ((GameObject *)obj)->anim.worldPosX;
  dy = py - ((GameObject *)obj)->anim.worldPosY;
  dz = pz - ((GameObject *)obj)->anim.worldPosZ;
  if ((*(u8 *)(romNode + 0x3b) & 1) != 0) {
    pitch = (s16)(0x8000 - getAngle(dx, dz));
  } else {
    pitch = (s16)((int)Curve_EvalCatmullRom(pitchS, t, (f32 *)0) + 0x8000);
  }
  if ((*(u8 *)(romNode + 0x3b) & 4) != 0) {
    roll = ((GameObject *)obj)->anim.rotZ;
  } else {
    roll = (int)Curve_EvalCatmullRom(rollS, t, (f32 *)0);
  }
  if ((*(u8 *)(romNode + 0x3b) & 2) != 0) {
    yaw = (s16)getAngle(dy, sqrtf(dx * dx + dz * dz));
    yaw = (int)((f32)yaw - Curve_EvalCatmullRom(yawS, t, (f32 *)0));
  } else {
    yaw = (int)Curve_EvalCatmullRom(yawS, t, (f32 *)0);
  }
  fov = Curve_EvalBSpline(fovS, t, (f32 *)0);
  pos[0] = px;
  pos[1] = py;
  pos[2] = pz;
  if (*((u8 *)param3 + 4) == 0 && param2 != 3) {
    cameraModeTestStrengthFn_8010b238((int)cam, pos, pitch, yaw, roll);
  } else {
    ((CameraObject *)cam)->anim.worldPosX = px;
    ((CameraObject *)cam)->anim.worldPosY = py;
    ((CameraObject *)cam)->anim.worldPosZ = pz;
    Obj_TransformWorldPointToLocal(((CameraObject *)cam)->anim.worldPosX, ((CameraObject *)cam)->anim.worldPosY,
                                   ((CameraObject *)cam)->anim.worldPosZ, (float *)(cam + 6),
                                   (float *)(cam + 8), (float *)(cam + 10), *(int *)(cam + 0x18));
    cam[0] = pitch;
    cam[1] = yaw;
    cam[2] = roll;
    ((CameraObject *)cam)->fov = fov;
  }
  *(f32 *)((char *)lbl_803DD560 + 0x58) = t;
}


/* Trivial 4b 0-arg blr leaves. */
void CameraModeTestStrength_release(void) {}
void CameraModeTestStrength_initialise(void) {}
void CameraModeCombat_copyToCurrent_nop(void) {}

extern undefined4 *lbl_803DD568;
extern f32 lbl_803E18C0;
extern f32 lbl_803E18C4;
extern f32 lbl_803E18C8;
extern f32 timeDelta;
extern void Rcp_DisableBlurFilter(void);

/*
 * --INFO--
 *
 * Function: fn_8010BF08
 * EN v1.0 Address: 0x8010BF08
 * EN v1.0 Size: 348b
 */
typedef struct {
    u8 pad[0xc];
    f32 x;
    f32 y;
    f32 z;
} CamPathEntry;

void fn_8010BF08(int control, float *outX, float *outY, float *outZ, void *inFloatPtr)
{
  int cameraObj;
  CamPathEntry *paths;
  int settings;
  u8 curIdx;
  float t;
  float lim;

  settings = *(int *)(control + 0x11c);
  cameraObj = *(int *)(control + 0xa4);
  paths = *(CamPathEntry **)(settings + 0x74);
  curIdx = *(u8 *)(settings + 0xe4);
  if ((u32)curIdx != (u32)*(u8 *)(*(int **)&lbl_803DD568 + 0x14/4)) {
    *(u8 *)((char *)*(int **)&lbl_803DD568 + 0x13) = *(u8 *)((char *)*(int **)&lbl_803DD568 + 0x14);
    *(float *)((char *)*(int **)&lbl_803DD568 + 0x18) = lbl_803E18C0;
  }
  t = *(float *)((char *)*(int **)&lbl_803DD568 + 0x18);
  lim = lbl_803E18C4;
  if (t > lim) {
    t = -(lbl_803E18C8 * timeDelta) + t;
    *(float *)((char *)*(int **)&lbl_803DD568 + 0x18) = t;
    if (*(float *)((char *)*(int **)&lbl_803DD568 + 0x18) < lim) {
      *(float *)((char *)*(int **)&lbl_803DD568 + 0x18) = lim;
      *(u8 *)((char *)*(int **)&lbl_803DD568 + 0x13) = *(u8 *)(settings + 0xe4);
    }
    {
      u8 ci = *(u8 *)((char *)*(int **)&lbl_803DD568 + 0x13);
      u8 ti = *(u8 *)(settings + 0xe4);
      float dx = paths[ci].x - paths[ti].x;
      float dy = paths[ci].y - paths[ti].y;
      float dz = paths[ci].z - paths[ti].z;
      float w = *(float *)((char *)*(int **)&lbl_803DD568 + 0x18);
      dx *= w;
      dy *= w;
      dz *= w;
      dx += paths[ti].x;
      dy += paths[ti].y;
      dz += paths[ti].z;
      *outX = dx - *(float *)(cameraObj + 0x18);
      *outY = dy - *(float *)inFloatPtr;
      *outZ = dz - *(float *)(cameraObj + 0x20);
    }
  } else {
    *outX = paths[*(u8 *)(settings + 0xe4)].x - *(float *)(cameraObj + 0x18);
    *outY = paths[*(u8 *)(settings + 0xe4)].y - *(float *)inFloatPtr;
    *outZ = paths[*(u8 *)(settings + 0xe4)].z - *(float *)(cameraObj + 0x20);
  }
  *(u8 *)((char *)*(int **)&lbl_803DD568 + 0x14) = *(u8 *)(settings + 0xe4);
}

/*
 * --INFO--
 *
 * Function: CameraModeCombat_free
 * EN v1.0 Address: 0x8010C068
 * EN v1.0 Size: 112b
 */
#pragma peephole off
#pragma scheduling off
typedef struct {
    u8 flag80 : 1;
} CamByte143;

void CameraModeCombat_free(int obj)
{
  if (*(void **)(obj + 0x11c) != NULL) {
    (*(void (**)(int))((char *)*(int *)gCameraInterface + 0x48))(0);
  }
  mm_free(lbl_803DD568);
  *(int *)&lbl_803DD568 = 0;
  Rcp_DisableBlurFilter();
  ((CamByte143 *)(obj + 0x143))->flag80 = 0;
}
#pragma scheduling reset
#pragma peephole reset
