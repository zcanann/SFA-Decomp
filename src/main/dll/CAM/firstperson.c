#include "ghidra_import.h"
#include "main/dll/CAM/firstperson.h"


#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_800068f4();
extern double FUN_800176f4();
extern undefined4 camcontrol_getTargetPosition();
extern double SeekTwiceBeforeRead();
extern double FUN_80293900();

extern int *gCameraInterface;
extern f32 *cameraMtxVar57;
extern f64 DOUBLE_803e1698;
extern f64 DOUBLE_803e16f8;
extern f32 lbl_803E1710;
extern f32 lbl_803E1714;
extern f64 DOUBLE_803e2318;
extern f64 DOUBLE_803e2378;
extern f32 lbl_803DC074;
extern f32 lbl_803E2314;
extern f32 lbl_803E2324;
extern f32 lbl_803E232C;
extern f32 lbl_803E2380;
extern f32 lbl_803E2384;
extern f32 lbl_803E2388;
extern f32 lbl_803E238C;
extern f32 lbl_803E2390;
extern f32 lbl_803E2394;

#define gCamcontrolModeSettings cameraMtxVar57

static inline f64 FirstPerson_U32AsDouble(u32 value) {
  u64 bits = CONCAT44(0x43300000, value);
  return *(f64 *)&bits;
}

static inline f64 FirstPerson_S32AsDouble(s32 value) {
  u64 bits = CONCAT44(0x43300000, (u32)value ^ 0x80000000);
  return *(f64 *)&bits;
}

/*
 * --INFO--
 *
 * Function: firstperson_updatePosition
 * EN v1.0 Address: 0x80105178
 * EN v1.0 Size: 1352b
 * EN v1.1 Address: 0x80105338
 * EN v1.1 Size: 1140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
typedef struct CamFlagByte {
    u8 flag : 1;
    u8 rest : 7;
} CamFlagByte;

typedef struct CamFlagByte2 {
    u8 pad : 1;
    u8 flag : 1;
    u8 rest : 6;
} CamFlagByte2;

extern f32 sqrtf();
extern f32 interpolate(f32 delta, f32 rate, f32 dt);
extern f32 PSVECMag(f32 *vec);
extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, int mapId);
extern f32 timeDelta;
extern f32 lbl_803E16AC;
extern f32 lbl_803E1694;
extern f32 lbl_803E16A4;
extern f32 lbl_803E1700;
extern f32 lbl_803E1704;
extern f32 lbl_803E1708;
extern f32 lbl_803E170C;

void firstperson_updatePosition(int param_1, short *param_2)
{
  f32 dx;
  f32 dz;
  f32 dy;
  f32 dist;
  f32 clamped;
  f32 targetX;
  f32 targetZ;
  f32 ratio;
  f32 speed;

  (*(void (**)(f32, int, f32 *, f32 *, f32 *, f32 *, int))(*gCameraInterface + 0x38))(
      gCamcontrolModeSettings[0x23], param_1, &dx, &dz, &dy, &dist, 1);
  dist = dy * dy + (dx * dx + dz * dz);
  if (dist > lbl_803E16AC) {
    dist = sqrtf(dist);
  }
  if (dist < lbl_803E1694) {
    dist = lbl_803E1694;
  }
  if (dist > lbl_803E1700 * gCamcontrolModeSettings[1]) {
    camcontrol_getTargetPosition(param_1, param_2, (float *)(param_1 + 0x18), (short *)(param_1 + 2));
    Obj_TransformWorldPointToLocal(*(f32 *)(param_1 + 0x18), *(f32 *)(param_1 + 0x1c),
                                   *(f32 *)(param_1 + 0x20), (f32 *)(param_1 + 0xc),
                                   (f32 *)(param_1 + 0x10), (f32 *)(param_1 + 0x14),
                                   *(int *)(param_1 + 0x30));
    *(f32 *)(param_1 + 0xb8) = *(f32 *)(param_1 + 0x18);
    *(f32 *)(param_1 + 0xbc) = *(f32 *)(param_1 + 0x1c);
    *(f32 *)(param_1 + 0xc0) = *(f32 *)(param_1 + 0x20);
    (*(void (**)(f32, int, f32 *, f32 *, f32 *, f32 *, int))(*gCameraInterface + 0x38))(
        gCamcontrolModeSettings[0x23], param_1, &dx, &dz, &dy, &dist, 1);
    dist = dy * dy + (dx * dx + dz * dz);
    if (dist > lbl_803E16AC) {
      dist = sqrtf(dist);
    }
    if (dist < lbl_803E1694) {
      dist = lbl_803E1694;
    }
  }

  if (dist > gCamcontrolModeSettings[1]) {
    clamped = gCamcontrolModeSettings[1];
    ((CamFlagByte *)((u8 *)gCamcontrolModeSettings + 0xc6))->flag = 0;
    ((CamFlagByte *)((u8 *)gCamcontrolModeSettings + 0xc8))->flag = 1;
  }
  else if (dist < *gCamcontrolModeSettings) {
    clamped = *gCamcontrolModeSettings;
    ((CamFlagByte *)((u8 *)gCamcontrolModeSettings + 0xc8))->flag = 0;
  }
  else {
    clamped = dist;
    ((CamFlagByte *)((u8 *)gCamcontrolModeSettings + 0xc8))->flag = 0;
  }

  targetX = *(f32 *)(param_1 + 0xc);
  targetZ = *(f32 *)(param_1 + 0x14);
  if ((((CamFlagByte *)((u8 *)gCamcontrolModeSettings + 0xc6))->flag == 0) && (clamped != dist) &&
      (lbl_803E16AC != gCamcontrolModeSettings[4])) {
    if (dist < lbl_803E16A4) {
      dist = lbl_803E16A4;
    }
    ratio = interpolate(dist - clamped, gCamcontrolModeSettings[4], timeDelta);
    ratio = (dist + ratio) / dist;
    if (ratio > lbl_803E16AC) {
      targetX = *(f32 *)(param_2 + 6) + dx / ratio;
      targetZ = *(f32 *)(param_2 + 10) + dy / ratio;
    }
  }

  dx = targetX - *(f32 *)(param_1 + 0xc);
  dy = targetZ - *(f32 *)(param_1 + 0x14);
  dist = sqrtf(dx * dx + dy * dy);
  if (dist > lbl_803E16AC) {
    dx = dx / dist;
    dy = dy / dist;
  }
  speed = PSVECMag((f32 *)(param_2 + 0x12)) * (lbl_803E1704 * timeDelta);
  if (speed < lbl_803E16A4) {
    speed = lbl_803E16A4;
  }
  dist = dist < lbl_803E16AC ? lbl_803E16AC : (dist > speed ? speed : dist);
  dist = dist < lbl_803E16AC ? lbl_803E16AC : (dist > lbl_803E1708 ? lbl_803E1708 : dist);
  *(f32 *)(param_1 + 0xc) = dx * dist + *(f32 *)(param_1 + 0xc);
  *(f32 *)(param_1 + 0x14) = dy * dist + *(f32 *)(param_1 + 0x14);

  if (gCamcontrolModeSettings[3] > gCamcontrolModeSettings[0x27]) {
    dx = *(f32 *)(param_1 + 0xc) - *(f32 *)(param_2 + 6);
    dy = *(f32 *)(param_1 + 0x14) - *(f32 *)(param_2 + 10);
    dist = sqrtf(dx * dx + dy * dy);
    if (dist < lbl_803E170C * *gCamcontrolModeSettings) {
      if (dist > lbl_803E16AC) {
        dx = dx / dist;
        dy = dy / dist;
      }
      dist = lbl_803E170C * *gCamcontrolModeSettings;
      *(f32 *)(param_1 + 0xc) = dist * dx + *(f32 *)(param_2 + 6);
      *(f32 *)(param_1 + 0x14) = dist * dy + *(f32 *)(param_2 + 10);
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: firstperson_loadSettings
 * EN v1.0 Address: 0x801056C0
 * EN v1.0 Size: 812b
 * EN v1.1 Address: 0x801057AC
 * EN v1.1 Size: 672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void firstperson_loadSettings(int param_1)
{
  float fVar1;
  int iVar4;

  iVar4 = (*(int (**)(void))(*gCameraInterface + 0xc))();
  gCamcontrolModeSettings[0x24] = gCamcontrolModeSettings[0x23];
  gCamcontrolModeSettings[0xf] = gCamcontrolModeSettings[2];
  gCamcontrolModeSettings[0x11] = gCamcontrolModeSettings[3];
  gCamcontrolModeSettings[0xb] = *gCamcontrolModeSettings;
  gCamcontrolModeSettings[0xd] = gCamcontrolModeSettings[1];
  gCamcontrolModeSettings[0x1b] = *(float *)(iVar4 + 0xb4);
  gCamcontrolModeSettings[0x17] = gCamcontrolModeSettings[6];
  gCamcontrolModeSettings[0x19] = gCamcontrolModeSettings[7];
  gCamcontrolModeSettings[0x15] = gCamcontrolModeSettings[5];
  gCamcontrolModeSettings[0x13] = gCamcontrolModeSettings[4];
  fVar1 = (f32)*(s8 *)(param_1 + 5);
  gCamcontrolModeSettings[0x23] = fVar1;
  gCamcontrolModeSettings[0x25] = fVar1;
  fVar1 = (f32)(u32)*(u8 *)(param_1 + 6);
  gCamcontrolModeSettings[2] = fVar1;
  gCamcontrolModeSettings[0x26] = fVar1;
  gCamcontrolModeSettings[0x10] = fVar1;
  fVar1 = (f32)(u32)*(u8 *)(param_1 + 8);
  gCamcontrolModeSettings[3] = fVar1;
  gCamcontrolModeSettings[0x27] = fVar1;
  gCamcontrolModeSettings[0x12] = fVar1;
  fVar1 = (f32)(u32)*(u8 *)(param_1 + 3);
  *gCamcontrolModeSettings = fVar1;
  gCamcontrolModeSettings[0xc] = fVar1;
  fVar1 = (f32)(u32)*(u8 *)(param_1 + 4);
  gCamcontrolModeSettings[1] = fVar1;
  gCamcontrolModeSettings[0xe] = fVar1;
  fVar1 = (f32)*(s8 *)(param_1 + 2);
  *(float *)(iVar4 + 0xb4) = fVar1;
  gCamcontrolModeSettings[0x1c] = fVar1;
  fVar1 = (f32)(u32)*(u8 *)(param_1 + 9);
  gCamcontrolModeSettings[6] = fVar1;
  gCamcontrolModeSettings[0x18] = fVar1;
  fVar1 = (f32)(u32)*(u8 *)(param_1 + 10);
  gCamcontrolModeSettings[7] = fVar1;
  gCamcontrolModeSettings[0x1a] = fVar1;
  if (*(u8 *)(param_1 + 0xb) == 0) {
    gCamcontrolModeSettings[0x14] = lbl_803E1714;
  }
  else {
    fVar1 = (f32)(u32)*(u8 *)(param_1 + 0xb) / lbl_803E1710;
    gCamcontrolModeSettings[4] = fVar1;
    gCamcontrolModeSettings[0x14] = fVar1;
  }
  if (*(u8 *)(param_1 + 0xc) == 0) {
    gCamcontrolModeSettings[0x16] = lbl_803E1714;
  }
  else {
    fVar1 = (f32)(u32)*(u8 *)(param_1 + 0xc) / lbl_803E1710;
    gCamcontrolModeSettings[5] = fVar1;
    gCamcontrolModeSettings[0x16] = fVar1;
  }
  *(u16 *)((int)gCamcontrolModeSettings + 0x82) = 0;
  *(u16 *)(gCamcontrolModeSettings + 0x21) = 0;
}

void CameraModeNormal_free(int obj)
{
  *(f32 *)((u8 *)cameraMtxVar57 + 0x74) = *(f32 *)(obj + 0x18);
  *(f32 *)((u8 *)cameraMtxVar57 + 0x78) = *(f32 *)(obj + 0x1c);
  *(f32 *)((u8 *)cameraMtxVar57 + 0x7c) = *(f32 *)(obj + 0x20);
  *(s16 *)((u8 *)cameraMtxVar57 + 0x86) = *(s16 *)(obj + 0x0);
  *(s16 *)((u8 *)cameraMtxVar57 + 0x88) = *(s16 *)(obj + 0x2);
  *(s16 *)((u8 *)cameraMtxVar57 + 0x8a) = *(s16 *)(obj + 0x4);
  ((CamFlagByte2 *)((u8 *)cameraMtxVar57 + 0xc6))->flag = 0;
}
