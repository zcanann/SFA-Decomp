#include "ghidra_import.h"
#include "main/dll/CAM/camshipbattle5C.h"
#include "main/dll/CAM/dll_5B.h"


#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_800033a8();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ,
                                           int obj);
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
extern u32 getButtonsJustPressed(int port);
extern char padGetCX(int port);
extern char padGetCY(int port);
extern double FUN_800176f4();
extern uint getAngle();
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017830();
extern int FUN_80017a98();
extern void *mmAlloc(int size,int heap,int flags);
extern int ObjHits_GetPriorityHit();
extern void* ObjGroup_GetObjects();
extern undefined4 FUN_80053bf0();
extern undefined4 FUN_800810d8();
extern undefined4 camcontrol_applyState();
extern undefined4 firstPersonPlaceCamera();
extern undefined4 firstPersonExit();
extern double fn_8010AEA8();
extern undefined4 FUN_80135814();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();
extern f32 sqrtf(f32 x);
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);
extern undefined4 FUN_80294c64();
extern undefined4 FUN_80294d00();

extern u8 framesThisStep;
extern undefined4* gCameraInterface;
extern undefined4* gRomCurveInterface;
extern undefined4* lbl_803DD548;
extern f32* lbl_803DD550;
extern undefined4* lbl_803DD558;
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

int fn_8010A47C(int curve, int *count, int tag);

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
  float fVar1;
  short sVar2;
  char cVar3;
  char cVar4;
  short *psVar5;
  double dVar6;
  double dVar7;
  undefined8 local_38;
  
  psVar5 = *(short **)(param_1 + 0x52);
  cVar3 = FUN_80006bd0(0);
  cVar4 = FUN_80006bc8(0);
  dVar6 = (double)((lbl_803E17E0 - *(float *)(param_1 + 0x5a)) / lbl_803E17E4);
  dVar7 = (double)lbl_803E17C4;
  if ((dVar7 <= dVar6) && (dVar7 = dVar6, (double)lbl_803E17E8 < dVar6)) {
    dVar7 = (double)lbl_803E17E8;
  }
  dVar6 = FUN_800176f4((f64)((f32)(s32)cVar3 *
                                -(f32)((f64)lbl_803E17F0 * dVar7 - (f64)lbl_803E17EC) -
                               *(f32 *)(lbl_803DD548 + 0x11c)),(f64)lbl_803E17F4,
                       (f64)timeDelta);
  *(float *)(lbl_803DD548 + 0x11c) = (float)((double)*(float *)(lbl_803DD548 + 0x11c) + dVar6);
  if ((lbl_803E17F8 < *(float *)(lbl_803DD548 + 0x11c)) &&
     (*(float *)(lbl_803DD548 + 0x11c) < lbl_803E17FC)) {
    *(float *)(lbl_803DD548 + 0x11c) = lbl_803E17C4;
  }
  fVar1 = lbl_803E1800 * ((f32)(s32)cVar4 / lbl_803E1804);
  *param_1 = (short)(int)(*(f32 *)(lbl_803DD548 + 0x11c) * timeDelta + (f32)(s32)*param_1);
  sVar2 = (short)(int)fVar1 - param_1[1];
  if (0x8000 < sVar2) {
    sVar2 = sVar2 + 1;
  }
  if (sVar2 < -0x8000) {
    sVar2 = sVar2 + -1;
  }
  dVar7 = FUN_800176f4((f64)(f32)(s32)sVar2,
                       (f64)(lbl_803E17E8 /
                               (f32)((f64)lbl_803E180C * dVar7 + (f64)lbl_803E1808)),
                       (f64)timeDelta);
  param_1[1] = (short)(int)((f64)(f32)(s32)param_1[1] + dVar7);
  if (0x3c00 < param_1[1]) {
    param_1[1] = 0x3c00;
  }
  if (param_1[1] < -0x3c00) {
    param_1[1] = -0x3c00;
  }
  *psVar5 = -0x8000 - *param_1;
  if (psVar5[0x22] == 1) {
    FUN_80294c64(psVar5,*psVar5);
  }
  if (*(float *)(lbl_803DD548 + 0x124) < *(float *)(lbl_803DD548 + 0x130)) {
    *(float *)(lbl_803DD548 + 0x130) = *(float *)(lbl_803DD548 + 0x124);
  }
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(lbl_803DD548 + 0x120);
  *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(lbl_803DD548 + 0x130);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(lbl_803DD548 + 0x128);
  if (*(char *)(lbl_803DD548 + 0x12d) < '\0') {
    dVar7 = (double)*(float *)(param_1 + 0x5a);
    cVar3 = FUN_80006bb8(0);
    dVar6 = (f64)(f32)((f64)(lbl_803E1810 * (f32)(s32)(-(int)cVar3)) *
                            (f64)timeDelta + dVar7);
    dVar7 = FUN_800069f8();
    FUN_800810d8(dVar7);
    dVar7 = (double)lbl_803E17FC;
    if ((dVar7 <= dVar6) && (dVar7 = dVar6, (double)lbl_803E17E0 < dVar6)) {
      dVar7 = (double)lbl_803E17E0;
    }
    if ((*(byte *)(lbl_803DD548 + 0x12d) >> 6 & 1) != 0) {
      if ((dVar7 == (double)*(float *)(param_1 + 0x5a)) &&
         ((*(byte *)(lbl_803DD548 + 0x12d) >> 5 & 1) != 0)) {
        FUN_80006810(0,0x3d8);
        *(byte *)(lbl_803DD548 + 0x12d) = *(byte *)(lbl_803DD548 + 0x12d) & 0xdf;
      }
      if ((dVar7 != (double)*(float *)(param_1 + 0x5a)) &&
         ((*(byte *)(lbl_803DD548 + 0x12d) >> 5 & 1) == 0)) {
        FUN_80006824(0,0x3d8);
        *(byte *)(lbl_803DD548 + 0x12d) = *(byte *)(lbl_803DD548 + 0x12d) & 0xdf | 0x20;
      }
    }
    *(float *)(param_1 + 0x5a) = (float)dVar7;
  }
  return;
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
extern void curveFn_80010dc0(void);
extern void curveFn_80010d54(void);
extern void curvesMove(void *curve);
extern int fn_802966D4(int obj, int *out);

int firstPersonEnter(u8 *cam, s16 *p2)
{
  u8 *state;
  int flag;
  int conv;
  int other;
  f32 f2;

  *(f32 *)(cam + 24) = *(f32 *)((char *)lbl_803DD548 + 288);
  *(f32 *)(cam + 28) = *(f32 *)((char *)lbl_803DD548 + 292);
  *(f32 *)(cam + 32) = *(f32 *)((char *)lbl_803DD548 + 296);
  *(s16 *)(cam + 2) = 0;
  flag = 0;
  if (*(f32 *)(cam + 244) <= lbl_803E17C4) {
    flag = 1;
  }
  conv = (int)(lbl_803E1814 * *(f32 *)(cam + 244));
  state = *(u8 **)(cam + 164);
  if (conv < 1) {
    conv = 1;
  }
  if (state != NULL) {
    state[54] = (u8)conv;
    if (Obj_GetPlayerObject() == (int)state) {
      if (fn_802966D4((int)state, &other) != 0) {
        *(u8 *)(other + 54) = (u8)conv;
        if (*(u8 *)(other + 54) == 1) {
          *(u8 *)(other + 54) = 0;
        }
      }
    }
  }
  if (flag != 0) {
    *(int *)((char *)lbl_803DD548 + 252) = (int)((char *)lbl_803DD548 + 64);
    *(int *)((char *)lbl_803DD548 + 256) = 0;
    *(int *)((char *)lbl_803DD548 + 260) = 0;
    *(int *)((char *)lbl_803DD548 + 264) = 4;
    *(int *)((char *)lbl_803DD548 + 268) = (int)&curveFn_80010dc0;
    *(int *)((char *)lbl_803DD548 + 272) = (int)&curveFn_80010d54;
    *(int *)((char *)lbl_803DD548 + 248) = 0;
    *(f32 *)((char *)lbl_803DD548 + 64) = (f32)(s32)*(s16 *)cam;
    *(f32 *)((char *)lbl_803DD548 + 68) = (f32)(s32)(0x8000 - p2[0]);
    f2 = *(f32 *)((char *)lbl_803DD548 + 64) - *(f32 *)((char *)lbl_803DD548 + 68);
    if (f2 < lbl_803E1818 && f2 > lbl_803E181C) {
      *(f32 *)((char *)lbl_803DD548 + 68) = *(f32 *)((char *)lbl_803DD548 + 64);
    } else if (f2 > lbl_803E17C8 || f2 < lbl_803E17CC) {
      if (*(f32 *)((char *)lbl_803DD548 + 64) < lbl_803E17C4) {
        *(f32 *)((char *)lbl_803DD548 + 64) += lbl_803E17D0;
      } else if (*(f32 *)((char *)lbl_803DD548 + 68) < lbl_803E17C4) {
        *(f32 *)((char *)lbl_803DD548 + 68) += lbl_803E17D0;
      }
    }
    *(f32 *)((char *)lbl_803DD548 + 72) = lbl_803E17C4;
    *(f32 *)((char *)lbl_803DD548 + 76) = lbl_803E17C4;
    curvesMove((char *)lbl_803DD548 + 120);
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

  cur = (u8 *)(*(int (**)(void))(*(int *)gCameraInterface + 0xc))();
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
#pragma peephole off
#pragma scheduling off
void CameraModeViewfinder_free(int param_1)
{
  int iVar1;
  int iVar2;
  int local_18 [5];

  *(ushort *)(*(int *)(param_1 + 0xa4) + 6) = *(ushort *)(*(int *)(param_1 + 0xa4) + 6) & ~0x4000;
  FUN_80053bf0(0);
  iVar2 = *(int *)(param_1 + 0xa4);
  if (iVar2 != 0) {
    *(undefined *)(iVar2 + 0x36) = 0xff;
    iVar1 = FUN_80017a98();
    if (iVar1 == iVar2) {
      FUN_80294d00(iVar2,local_18);
      if (local_18[0] != 0) {
        *(undefined *)(local_18[0] + 0x36) = 0xff;
        if (*(char *)(local_18[0] + 0x36) == '\x01') {
          *(undefined *)(local_18[0] + 0x36) = 0;
        }
      }
    }
  }
  FUN_80006810(0,0x3d8);
  FUN_80017814(lbl_803DD548);
  lbl_803DD548 = 0;
  FUN_800810d8((double)lbl_803E17E0);
  return;
}
#pragma scheduling reset
#pragma peephole reset

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
void CameraModeViewfinder_update(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

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
void CameraModeViewfinder_init(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 *param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
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
    (*(void (**)(int, int, int, int, int, int, int))(*(int *)gCameraInterface + 0x1c))(0x42, 0, 1, 0, 0, 0, 0xff);
    return;
  }
  move = lbl_803E1840;
  held = getButtonsHeld(0);
  if ((held & 8) != 0) {
    move = lbl_803E1844 * *lbl_803DD550;
  }
  if ((held & 4) != 0) {
    move = lbl_803E1848 * *lbl_803DD550;
  }
  absMove = (move < lbl_803E1840) ? -move : move;
  absVel = (lbl_803DD550[1] < lbl_803E1840) ? -lbl_803DD550[1] : lbl_803DD550[1];
  factor = lbl_803E1850;
  if (absMove < absVel) {
    factor = lbl_803E184C;
  }
  lbl_803DD550[1] = factor * (move - lbl_803DD550[1]) + lbl_803DD550[1];
  *lbl_803DD550 = *lbl_803DD550 + lbl_803DD550[1];
  if (*lbl_803DD550 < lbl_803E1854) {
    *lbl_803DD550 = lbl_803E1854;
  }
  if (*lbl_803DD550 > lbl_803E1858) {
    *lbl_803DD550 = lbl_803E1858;
  }
  *(s16 *)cam = (s16)(*(s16 *)cam - (s8)padGetCX(0) * 3);
  *(s16 *)(cam + 2) = (s16)(*(s16 *)(cam + 2) + (s8)padGetCY(0) * 3);
  {
    f32 cosYaw = fn_80293E80(lbl_803E185C * (f32)(s32)(*(s16 *)cam - 0x4000) / lbl_803E1860);
    f32 sinYaw = sin(lbl_803E185C * (f32)(s32)(*(s16 *)cam - 0x4000) / lbl_803E1860);
    f32 sinPitch = sin(lbl_803E185C * (f32)(s32)(*(s16 *)(cam + 2) - 0x4000) / lbl_803E1860);
    f32 cosPitch = fn_80293E80(lbl_803E185C * (f32)(s32)(*(s16 *)(cam + 2) - 0x4000) / lbl_803E1860);
    radius = *lbl_803DD550;
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
  if (lbl_803DD550 == (f32 *)0x0) {
    lbl_803DD550 = (f32 *)mmAlloc(8,0xf,0);
  }
  *lbl_803DD550 = lbl_803E1870;
  lbl_803DD550[1] = lbl_803E1840;
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
void *fn_80109B04(int filter1, int filter2, f32 x, f32 y, f32 z)
{
    void *best;
    double bestDist;
    int count;
    int *list;
    int i;
    int *obj;
    f32 dx, dy, dz;
    double dist;

    bestDist = lbl_803E1878;
    best = NULL;
    list = (int *)ObjGroup_GetObjects(7, &count);
    for (i = 0; i < count; i++) {
        obj = (int *)*list;
        if (*(s16 *)((char *)obj + 0x44) == filter2 &&
            *(u8 *)(*(int *)((char *)obj + 0x4c) + 0x18) == filter1) {
            dx = x - *(f32 *)((char *)obj + 0x18);
            dy = y - *(f32 *)((char *)obj + 0x1c);
            dz = z - *(f32 *)((char *)obj + 0x20);
            dist = sqrtf(dy*dy + dx*dx + dz*dz);
            if (dist < bestDist) {
                bestDist = dist;
                best = obj;
            }
        }
        list++;
    }
    return best;
}

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
  
  if (*(byte *)((int)lbl_803DD558 + 0xf5) != 0) {
    (*(void (**)(int, int, int, int, int, int, int))(*(int *)gCameraInterface + 0x1c))(0x42,0,1,0,0,0,0xff);
  }
  else {
    iVar3 = *(int *)(param_1 + 0x52);
    iVar4 = *(int *)(*lbl_803DD558 + 0x4c);
    if ((*(byte *)(iVar4 + 0x1b) & 1) == 0) {
      *param_1 = *(short *)(iVar4 + 0x1c) + -0x8000;
    }
    if ((*(byte *)(iVar4 + 0x1b) & 2) == 0) {
      param_1[1] = *(short *)(iVar4 + 0x1e);
    }
    if ((*(byte *)(iVar4 + 0x1b) & 4) == 0) {
      param_1[2] = *(short *)(iVar4 + 0x20);
    }
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(*lbl_803DD558 + 0x18);
    *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(*lbl_803DD558 + 0x1c);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(*lbl_803DD558 + 0x20);
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
  u8 *state = *(u8 **)(cam + 164);
  int obj;
  u8 *setup;
  s16 yaw;
  s16 pitch;
  s16 roll;
  f32 dx, dy, dz;

  if (lbl_803DD558 == NULL) {
    lbl_803DD558 = (undefined4 *)mmAlloc(248, 15, 0);
  }
  *(u8 *)((int)lbl_803DD558 + 244) = 1;
  *(u8 *)((int)lbl_803DD558 + 245) = 0;
  obj = (int)fn_80109B04(*p3, 18, *(f32 *)(state + 24), *(f32 *)(state + 28), *(f32 *)(state + 32));
  if (obj == 0) {
    *(u8 *)((int)lbl_803DD558 + 245) = 1;
    return;
  }
  *(int *)lbl_803DD558 = obj;
  setup = *(u8 **)(obj + 76);
  dx = *(f32 *)(obj + 24) - *(f32 *)(state + 24);
  dy = *(f32 *)(obj + 28) - *(f32 *)(state + 28);
  dz = *(f32 *)(obj + 32) - *(f32 *)(state + 32);
  if ((setup[27] & 1) != 0) {
    yaw = (s16)(0x8000 - getAngle(dx, dz));
  } else {
    yaw = (s16)(*(s16 *)(setup + 28) + 0x8000);
  }
  if ((setup[27] & 2) != 0) {
    pitch = (s16)getAngle(dy, sqrtf(dx * dx + dz * dz)) - *(s16 *)(setup + 30);
  } else {
    pitch = *(s16 *)(setup + 30);
  }
  if ((setup[27] & 4) != 0) {
    roll = *(s16 *)(state + 4);
  } else {
    roll = *(s16 *)(setup + 32);
  }
  *(f32 *)(cam + 24) = *(f32 *)(obj + 24);
  *(f32 *)(cam + 28) = *(f32 *)(obj + 28);
  *(f32 *)(cam + 32) = *(f32 *)(obj + 32);
  *(s16 *)(cam + 0) = yaw;
  *(s16 *)(cam + 2) = pitch;
  *(s16 *)(cam + 4) = roll;
  *(f32 *)(cam + 180) = (f32)(u32)setup[26];
  Obj_TransformWorldPointToLocal(*(f32 *)(cam + 24), *(f32 *)(cam + 28), *(f32 *)(cam + 32),
                                 (f32 *)(cam + 12), (f32 *)(cam + 16), (f32 *)(cam + 20),
                                 *(int *)(cam + 48));
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

  curve = (*(int (**)(int))(*(int *)gRomCurveInterface + 0x1c))(*p1);
  found = 1;
  for (i = 0; i < 5; i++) {
    if (*(int *)(curve + 28 + i * 4) > -1 &&
        ((s8)*(s8 *)(curve + 27) & (1 << i)) == 0) {
      linked = (*(int (**)(int))(*(int *)gRomCurveInterface + 0x1c))(*(int *)(curve + 28 + i * 4));
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
        linked = (*(int (**)(int))(*(int *)gRomCurveInterface + 0x1c))(*(int *)(curve + 28 + i * 4));
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
    curve = (*(int (**)(int))(*(int *)gRomCurveInterface + 0x1c))(*p1);
    pathcam_findTaggedNodeWindow(curve, window, tag);
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
  curve = (*(int (**)(int))(*(int *)gRomCurveInterface + 0x1c))(*p1);
  fn_8010A47C(curve, &count, tag);
  curve = (*(int (**)(int))(*(int *)gRomCurveInterface + 0x1c))(*p2);
  *p2 = *(int *)(fn_8010A47C(curve, &dummy, tag) + 20);
  for (k = 0; k < count; k++) {
    curve = (*(int (**)(int))(*(int *)gRomCurveInterface + 0x1c))(*p2);
    for (i = 0; i < 5; i++) {
      if (*(int *)(curve + 28 + i * 4) > -1 &&
          ((s8)*(s8 *)(curve + 27) & (1 << i)) == 0) {
        linked = (*(int (**)(int))(*(int *)gRomCurveInterface + 0x1c))(*(int *)(curve + 28 + i * 4));
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
          linked = (*(int (**)(int))(*(int *)gRomCurveInterface + 0x1c))
                     (*(int *)(curve + i * 4 + 0x1c));
          if ((linked != 0) &&
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
extern void mm_free(void *);
#pragma scheduling off
#pragma peephole off
void CameraModeDebug_free(void) { mm_free(lbl_803DD550); lbl_803DD550 = 0; }
void CameraModeStatic_free(void) { mm_free(lbl_803DD558); lbl_803DD558 = 0; }
#pragma peephole reset
#pragma scheduling reset
