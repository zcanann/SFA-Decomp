#include "ghidra_import.h"
#include "main/dll/CAM/cutCam.h"


#pragma peephole off
#pragma scheduling off
extern int FUN_800033a8();
extern undefined4 FUN_800068f4();
extern undefined4 FUN_800068f8();
extern undefined4 FUN_80006a88();
extern undefined4 FUN_80006a8c();
extern ushort FUN_80006be8();
extern uint FUN_80006c00();
extern f32 Curve_EvalHermite(f32 param_1,float *param_2,float *param_3);
extern ushort getPadFn_80014d9c(int controller);
extern ushort getButtonsJustPressed(int controller);
extern uint FUN_80017730();
extern int objBboxFn_800640cc(float *p1, float *p2, float *p3, int *p4, int *p5, int p6, int p7, int p8, int p9);
extern void hitDetectFn_80067958(int a, float *b, float *c, int d, int e, int f);
extern void hitDetectFn_800691c0(int a, void *b, int c, int d);
extern void hitDetect_calcSweptSphereBounds(uint *boundsOut,float *startPoints,float *endPoints,
                        float *radii,int pointCount);
extern int FUN_8007f7c0();
extern int getCurSeqNo();
extern void cameraSetInterpMode(u8);
extern undefined4 camcontrol_applyState();
extern undefined4 FUN_802473cc();
extern undefined4 FUN_8028681c();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286868();
extern undefined4 FUN_80286888();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint FUN_80294bf4();
extern int FUN_80294c88();
extern int FUN_80294d10();
extern undefined4 FUN_80294d78();
extern void cameraGetPrevPos2();
extern int fn_80295C0C(int);
extern int objFn_802962b4(int);
extern int objFn_80296700(int);
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);
extern f64 sqrtf(f64 x);
extern int getAngle(f32 dx, f32 dy);

extern undefined4 DAT_803a4ed8;
extern undefined4 gCamcontrolTargetTypeMask;
extern undefined4* DAT_803dd6d0;
extern int *gCameraInterface;
extern undefined4 gCamcontrolTargetState;
extern undefined4 DAT_803de143;
extern undefined4 DAT_803de144;
extern undefined4 DAT_803de188;
extern undefined4 DAT_803de18c;
extern undefined4 gCamcontrolCurrentActionId;
extern undefined4* gCamcontrolState;
extern u8 lbl_803DD528;
extern undefined4* gCamcontrolModeSettings;
extern f32 *cameraMtxVar57;
extern u8 framesThisStep;
extern f64 DOUBLE_803e2318;
extern f64 lbl_803E1698;
extern f32 lbl_803E1688;
extern f32 lbl_803E168C;
extern f32 lbl_803E1690;
extern f32 lbl_803E1694;
extern f32 lbl_803E16A4;
extern f32 lbl_803E16AC;
extern f32 lbl_803DE1A4;
extern f32 lbl_803E2304;
extern f32 lbl_803E2308;
extern f32 lbl_803E2314;
extern f32 lbl_803E2320;
extern f32 lbl_803E2324;
extern f32 lbl_803E2328;
extern f32 lbl_803E232C;
extern f32 lbl_803E2330;
extern f32 lbl_803E2334;
extern f32 lbl_803E2338;
extern f32 lbl_803E233C;
extern f32 lbl_803E2340;
extern f32 lbl_803E2344;
extern f32 lbl_803E2348;
extern f32 lbl_803E234C;

/*
 * --INFO--
 *
 * Function: camcontrol_traceMove
 * EN v1.0 Address: 0x80103768
 * EN v1.0 Size: 284b
 * EN v1.1 Address: 0x801037C0
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
int
camcontrol_traceMove(float *param_2,float *param_3,float *param_4,u8 *param_5,
                     char param_6,u8 param_7,u8 param_8,float param_1)
{
  u8 cVar2;
  undefined4 uVar1;
  float local_40 [3];
  uint auStack_34 [9];

  if (param_4 == (float *)0x0) {
    param_4 = local_40;
  }
  *param_4 = *param_3;
  param_4[1] = param_3[1];
  param_4[2] = param_3[2];
  *(float *)(param_5 + 0x40) = param_1;
  *(s8 *)(param_5 + 0x50) = -1;
  *(s8 *)(param_5 + 0x54) = param_6;
  cVar2 = '\0';
  *(undefined2 *)(param_5 + 0x6c) = 0;
  if (param_8 != '\0') {
    cVar2 = objBboxFn_800640cc(param_2,param_4,(float *)0x1,(int *)0x0,(int *)0x0,0x10,0xffffffff,0xff,0);
  }
  lbl_803DD528 = cVar2;
  if (param_7 != '\0') {
    hitDetect_calcSweptSphereBounds(auStack_34,param_2,param_4,(float *)(param_5 + 0x40),1);
    hitDetectFn_800691c0(0,auStack_34,0x240,'\x01');
  }
  hitDetectFn_80067958(0, param_2, param_4, 1, (int)param_5, 0);
  uVar1 = 0;
  if ((lbl_803DD528 == '\0') && (*(short *)(param_5 + 0x6c) == 0)) {
    uVar1 = 1;
  }
  return uVar1;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: camcontrol_traceFromTarget
 * EN v1.0 Address: 0x80103888
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x80103900
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined camcontrol_traceFromTarget(float *param_1,int param_2,float *param_3)
{
  float local_88;
  float local_84;
  float local_80;
  undefined auStack_7c [111];

  if (*(short *)(param_2 + 0x44) == 1) {
    cameraGetPrevPos2(param_2,&local_88,&local_84,&local_80);
  }
  else {
    local_88 = *(float *)(param_2 + 0x18);
    local_84 = *(float *)(param_2 + 0x1c) + cameraMtxVar57[0x23];
    local_80 = *(float *)(param_2 + 0x20);
  }
  camcontrol_traceMove(&local_88,param_1,param_3,auStack_7c,3,'\x01','\x01',(double)lbl_803E1688);
  return auStack_7c[110];
}

/*
 * --INFO--
 *
 * Function: camcontrol_getTargetPosition
 * EN v1.0 Address: 0x801039C4
 * EN v1.0 Size: 596b
 * EN v1.1 Address: 0x801039A4
 * EN v1.1 Size: 584b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
undefined camcontrol_getTargetPosition(int param_1,short *param_2,float *param_3,short *param_4)
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
  uint ang;
  int d;

  cosv = fn_80293E80((lbl_803E168C * (f32)*param_2) / lbl_803E1690);
  sinv = sin((lbl_803E168C * (f32)*param_2) / lbl_803E1690);
  d2 = cameraMtxVar57[1] * cameraMtxVar57[1] - cameraMtxVar57[2] * cameraMtxVar57[2];
  if (d2 < lbl_803E1694) {
    d2 = lbl_803E1694;
  }
  d2 = sqrtf(d2);
  pos[0] = cosv * d2 + *(float *)(param_2 + 0xc);
  pos[1] = cameraMtxVar57[2] + (*(float *)(param_2 + 0xe) + cameraMtxVar57[0x23]);
  pos[2] = sinv * d2 + *(float *)(param_2 + 0x10);
  if (param_2[0x22] == 1) {
    cameraGetPrevPos2((int)param_2,&prev[0],&prev[1],&prev[2]);
  }
  else {
    prev[0] = *(float *)(param_2 + 0xc);
    prev[1] = *(float *)(param_2 + 0xe) + cameraMtxVar57[0x23];
    prev[2] = *(float *)(param_2 + 0x10);
  }
  camcontrol_traceMove(prev,pos,param_3,box,3,'\x01','\x01',lbl_803E1688);
  (*(void (**)(int, f32 *, f32 *, f32 *, f32 *, f32, int))(*gCameraInterface + 0x38))
      (param_1, &a, &b, &c, &d2, cameraMtxVar57[0x23], 0);
  b = *(float *)(param_1 + 0x1c) -
      (*(float *)(param_2 + 0xe) + cameraMtxVar57[0x23]);
  ang = getAngle(b,d2);
  d = (ang & 0xffff) - (u16)*(s16 *)(param_1 + 2);
  if (0x8000 < d) {
    d = d - 0xffff;
  }
  if (d < -0x8000) {
    d = d + 0xffff;
  }
  if (param_4 != (short *)0x0) {
    *param_4 = *(s16 *)(param_1 + 2) + d;
  }
  return box[110];
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: camcontrol_updateTargetAction
 * EN v1.0 Address: 0x80103C18
 * EN v1.0 Size: 488b
 * EN v1.1 Address: 0x80103BEC
 * EN v1.1 Size: 496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void camcontrol_updateTargetAction(int param_1,int param_2)
{
  short sVar1;
  int uVar2;
  int iVar3;
  CamcontrolAction43Payload local_28;
  CamcontrolAction44Payload local_24;
  longlong local_18;
  
  if (*(void **)(param_2 + 0xc0) == NULL) {
    uVar2 = getButtonsJustPressed(0);
    if (*(void **)(param_1 + 0x124) != NULL) {
      sVar1 = *(short *)(*(int *)(param_1 + 0x124) + 0x44);
      if (((sVar1 == 0x1c) || (sVar1 == 0x2a)) && (*(short *)(param_2 + 0x44) == 1)) {
        iVar3 = objFn_80296700(param_2);
        if ((iVar3 != 0) && (iVar3 = fn_80295C0C(param_2), iVar3 != 0)) {
          goto action_49;
        }
      }
    }
    if ((*(byte *)(param_1 + 0x141) & 2) != 0) {
      goto action_49;
    }
    goto check_action_44;
action_49:
    cameraSetInterpMode(1);
    (*(code *)(*gCameraInterface + 0x1c))(0x49,1,0,4,param_1 + 0x124,0x3c,0xff);
    goto done;
check_action_44:
    if ((((uVar2 & 0x10) != 0) && (*(short *)(param_2 + 0x44) == 1)) &&
       (iVar3 = objFn_802962b4(param_2), iVar3 != 0)) {
      local_24.distance = *cameraMtxVar57;
      local_24.yOffset = cameraMtxVar57[2];
      local_18 = (longlong)(int)cameraMtxVar57[0x23];
      local_24.height = (int)cameraMtxVar57[0x23];
      cameraSetInterpMode(0);
      (*(code *)(*gCameraInterface + 0x1c))(0x44,1,0,0xc,&local_24,0xf,0xfe);
    }
    else {
      iVar3 = getCurSeqNo();
      if (((iVar3 == 0) && (uVar2 = getPadFn_80014d9c(0), (uVar2 & 0x40) != 0)) &&
         ((*(short *)(param_1 + 6) & 4) == 0)) {
        local_28.action = 5;
        local_28.enabled = 1;
        local_28.immediate = 1;
        (*(code *)(*gCameraInterface + 0x1c))(0x43,1,0,4,&local_28,0,0xff);
      }
    }
    goto done;
done:
    ;
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: cameraFn_80103b40
 * EN v1.0 Address: 0x80103B40
 * EN v1.0 Size: 1280b
 */
extern u32 OSGetTick(void);
extern f32 lbl_803E16A0;
extern f32 lbl_803E16A4;
extern f32 lbl_803E16A8;
extern f32 lbl_803E16B0;
extern f32 lbl_803E16B4;
extern f32 lbl_803E16B8;
extern f32 lbl_803E16BC;
extern f32 lbl_803E16C0;
extern f32 lbl_803E16C4;
extern f32 lbl_803E16C8;
extern f32 lbl_803E16CC;
extern f32 lbl_803DD52C;

int cameraFn_80103b40(short *cam, f32 *outA, f32 *outB, int angle)
{
  int tgt0;
  float probe[35];
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
  float *pA;
  float *pB;
  float *pp;
  float *pA0;
  float *pB0;
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

  OSGetTick();
  result = 0;
  (*(void (**)(short *, f32 *, f32 *, f32 *, f32 *, f32, int))(*gCameraInterface + 0x38))
      (cam, &spinB, &spinC, &spinD, &spinA, *(f32 *)((char *)cameraMtxVar57 + 0x8c), 0);
  tgt0 = *(int *)((char *)cam + 0xa4);
  probe[1] = *(f32 *)((char *)cam + 0x1c);
  pathA[0] = *(f32 *)((char *)cam + 0x18);
  pathA[1] = *(f32 *)((char *)cam + 0x1c);
  pathA[2] = *(f32 *)((char *)cam + 0x20);
  pathB[0] = pathA[0];
  pathB[1] = pathA[1];
  pathB[2] = pathA[2];
  if (*(short *)(tgt0 + 0x44) == 1) {
    cameraGetPrevPos2(tgt0, &prev[0], &prev[1], &prev[2]);
  }
  else {
    prev[0] = *(f32 *)(tgt0 + 0x18);
    prev[1] = *(f32 *)(tgt0 + 0x1c) + *(f32 *)((char *)cameraMtxVar57 + 0x8c);
    prev[2] = *(f32 *)(tgt0 + 0x20);
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
  while ((s16)s <= 0x5a) {
    if (found1 == -1) {
      dx = spinD;
      dz = spinB;
      tgt = *(int *)((char *)cam + 0xa4);
      rad = (lbl_803E168C * (f32)(s16)ang) / lbl_803E1690;
      cosv = fn_80293E80(rad);
      sinv = sin(rad);
      t = dz * sinv - dx * cosv;
      v = t * cosv + dx * sinv;
      t = t + *(f32 *)(tgt + 0x18);
      probe[0] = t;
      v = v + *(f32 *)(tgt + 0x20);
      probe[2] = v;
      pA[3] = probe[0];
      pA[4] = probe[1];
      pA[5] = probe[2];
      if (camcontrol_traceMove(prev, pp, (float *)0x0, box, 7, '\0', '\0', lbl_803E16A0) != 0) {
        found1 = i;
      }
    }
    if (found2 == -1) {
      dx = spinD;
      dz = spinB;
      tgt = *(int *)((char *)cam + 0xa4);
      rad = (lbl_803E168C * (f32)(s16)(-s * 0xb6)) / lbl_803E1690;
      cosv = fn_80293E80(rad);
      sinv = sin(rad);
      t = dz * sinv - dx * cosv;
      v = t * cosv + dx * sinv;
      t = t + *(f32 *)(tgt + 0x18);
      probe[0] = t;
      v = v + *(f32 *)(tgt + 0x20);
      probe[2] = v;
      pB[3] = probe[0];
      pB[4] = probe[1];
      pB[5] = probe[2];
      if (camcontrol_traceMove(prev, pp, (float *)0x0, box, 7, '\0', '\0', lbl_803E16A0) != 0) {
        found2 = i;
      }
    }
    pA = pA + 3;
    pB = pB + 3;
    i = i + 1;
    ang = ang + 0xaaa;
    s = s + 0xf;
  }
  if (found1 == -1) {
    found1 = 6;
  }
  else {
    for (i = 0; i <= found1; i = i + 1) {
      if (camcontrol_traceMove(pA0, pathA + (i + 1) * 3, (float *)0x0, box, 7,
                               '\0', '\0', lbl_803E16A0) == 0) {
        found1 = 6;
        break;
      }
      pA0 = pA0 + 3;
    }
  }
  if (found2 == -1) {
    found2 = 6;
  }
  else {
    for (i = 0; i <= found2; i = i + 1) {
      if (camcontrol_traceMove(pB0, pathB + (i + 1) * 3, (float *)0x0, box, 7,
                               '\0', '\0', lbl_803E16A0) == 0) {
        found2 = 6;
        break;
      }
      pB0 = pB0 + 3;
    }
  }
  dir = 0;
  if (found1 < found2) {
    dir = 1;
  }
  else if (found2 < found1) {
    dir = -1;
  }
  else if (found1 < 6) {
    dir = 1;
  }
  if (dir != 0) {
    f32 f;
    f32 g;
    d = (0x8000 - *cam) - (angle & 0xffff);
    if (0x8000 < d) {
      d = d - 0xffff;
    }
    if (d < -0x8000) {
      d = d + 0xffff;
    }
    if (d < 0) {
      d = -d;
    }
    f = *(f32 *)((char *)cam + 0xc4) * *(f32 *)((char *)cam + 0xc4);
    if (f < lbl_803E16A4) {
      f = lbl_803E16A4;
    }
    g = f * lbl_803E16A8;
    g = lbl_803E16AC + g;
    g = g + (f32)d / lbl_803E16B0;
    if (g < lbl_803E16B4) {
      g = lbl_803E16B4;
    }
    if (lbl_803E16B8 < g) {
      g = lbl_803E16B8;
    }
    if (dir == -1) {
      g = -g;
    }
    g = g * lbl_803DD52C + *(f32 *)((char *)cameraMtxVar57 + 0x28);
    if (g > lbl_803E16BC) {
      g = lbl_803E16BC;
    }
    else if (g < lbl_803E16C0) {
      g = lbl_803E16C0;
    }
    *(f32 *)((char *)cameraMtxVar57 + 0x28) = g;
    result = 1;
  }
  return result;
}

/*
 * --INFO--
 *
 * Function: camMoveFn_80104040
 * EN v1.0 Address: 0x80104040
 * EN v1.0 Size: 1280b
 */
typedef struct {
    u8 bit80 : 1;
    u8 rest : 7;
} CamcontrolByteC6;

extern void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ,
                                           int xform);
extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ,
                                           int xform);

void camMoveFn_80104040(int cam, short *tgt)
{
  float path[39];
  float endPts[39];
  u8 box[112];
  float radii[13];
  uint bounds[6];
  float prev[3];
  f32 outB[2];
  f32 outA[2];
  int ang;
  float *p;
  int i;
  int j;
  f32 kB;
  f32 kA;
  f32 dx;
  f32 dz;
  f32 cosv;
  f32 rad;
  f32 sinv;
  f32 t;
  f32 z;
  u8 trace;
  u8 blocked;
  s16 spin;

  Obj_TransformLocalPointToWorld(*(f32 *)(cam + 0xc), *(f32 *)(cam + 0x10), *(f32 *)(cam + 0x14),
                                 (f32 *)(cam + 0x18), (f32 *)(cam + 0x1c), (f32 *)(cam + 0x20),
                                 *(int *)(cam + 0x30));
  lbl_803DD528 = 0;
  if (*(short *)((char *)tgt + 0x44) == 1) {
    cameraGetPrevPos2((int)tgt, &prev[0], &prev[1], &prev[2]);
  }
  else {
    prev[0] = *(f32 *)((char *)tgt + 0x18);
    prev[1] = *(f32 *)((char *)tgt + 0x1c) + *(f32 *)((char *)cameraMtxVar57 + 0x8c);
    prev[2] = *(f32 *)((char *)tgt + 0x20);
  }
  path[0] = *(f32 *)(cam + 0x18);
  path[1] = *(f32 *)(cam + 0x1c);
  path[2] = *(f32 *)(cam + 0x20);
  dx = path[0] - prev[0];
  dz = path[2] - prev[2];
  i = 1;
  ang = 0xaaa;
  p = path + 3;
  kA = lbl_803E168C;
  kB = lbl_803E1690;
  do {
    rad = (kA * (f32)(s16)ang) / kB;
    cosv = fn_80293E80(rad);
    sinv = sin(rad);
    t = dx * sinv - dz * cosv;
    z = t * cosv + dz * sinv;
    z = z + *(f32 *)((char *)tgt + 0x20);
    p[0] = t + *(f32 *)((char *)tgt + 0x18);
    p[1] = *(f32 *)(cam + 0x1c);
    p[2] = z;
    rad = (kA * (f32)(s16)(-i * 0xaaa)) / kB;
    cosv = fn_80293E80(rad);
    sinv = sin(rad);
    t = dx * sinv - dz * cosv;
    z = t * cosv + dz * sinv;
    z = z + *(f32 *)((char *)tgt + 0x20);
    p[3] = t + *(f32 *)((char *)tgt + 0x18);
    p[4] = *(f32 *)(cam + 0x1c);
    p[5] = z;
    ang = ang + 0x1554;
    p = p + 6;
    i = i + 2;
  } while (i <= 0xc);
  for (j = 0; j <= 0xc; j = j + 1) {
    radii[j] = lbl_803E16A0;
    endPts[j * 3] = prev[0];
    endPts[j * 3 + 1] = prev[1];
    endPts[j * 3 + 2] = prev[2];
  }
  hitDetect_calcSweptSphereBounds(bounds, (float *)path, endPts, radii, 0xd);
  hitDetectFn_800691c0(0, bounds, 0x248, 1);
  trace = camcontrol_traceMove(prev, (float *)(cam + 0x18), (float *)0x0, box, 7,
                               '\0', '\0', lbl_803E16A0);
  blocked = 0;
  if (trace == 0) {
    blocked = 1;
  }
  *(u8 *)((char *)cameraMtxVar57 + 0xc0) = blocked;
  if (blocked != 0) {
    ((CamcontrolByteC6 *)((char *)cameraMtxVar57 + 0xc6))->bit80 = 0;
    if (cameraFn_80103b40((short *)cam, outA, outB, (int)tgt[0]) == 0) {
      *(f32 *)((char *)cameraMtxVar57 + 0x28) = lbl_803E16AC;
    }
  }
  if (lbl_803E16AC != *(f32 *)((char *)cameraMtxVar57 + 0x28)) {
    spin = (s16)(int)*(f32 *)((char *)cameraMtxVar57 + 0x28);
    if ((spin < -0x1e) || (0x1e < spin)) {
      rad = (lbl_803E168C * (f32)spin) / lbl_803E1690;
      cosv = fn_80293E80(rad);
      sinv = sin(rad);
      t = dx * sinv - dz * cosv;
      *(f32 *)(cam + 0x18) = t + *(f32 *)((char *)tgt + 0x18);
      z = t * cosv + dz * sinv;
      *(f32 *)(cam + 0x20) = z + *(f32 *)((char *)tgt + 0x20);
    }
    *(f32 *)((char *)cameraMtxVar57 + 0x28) = *(f32 *)((char *)cameraMtxVar57 + 0x28) * lbl_803E16C4;
    if ((*(f32 *)((char *)cameraMtxVar57 + 0x28) < lbl_803E16C8) &&
        (lbl_803E16CC < *(f32 *)((char *)cameraMtxVar57 + 0x28))) {
      *(f32 *)((char *)cameraMtxVar57 + 0x28) = lbl_803E16AC;
    }
  }
  Obj_TransformWorldPointToLocal(*(f32 *)(cam + 0x18), *(f32 *)(cam + 0x1c), *(f32 *)(cam + 0x20),
                                 (f32 *)(cam + 0xc), (f32 *)(cam + 0x10), (f32 *)(cam + 0x14),
                                 *(int *)(cam + 0x30));
}

/*
 * --INFO--
 *
 * Function: camcontrol_updateModeSettings
 * EN v1.0 Address: 0x80104540
 * EN v1.0 Size: 436b
 *
 * TODO: stub. Body adjusts gCamcontrolModeSettings fields with clamping.
 */
void camcontrol_updateModeSettings(int camera)
{
  f32 blend;
  f32 ratio;
  float curve[4];

  if (*(s16 *)((int)cameraMtxVar57 + 0x82) != 0) {
    *(s16 *)((int)cameraMtxVar57 + 0x82) -= framesThisStep;
    if (*(s16 *)((int)cameraMtxVar57 + 0x82) < 0) {
      *(s16 *)((int)cameraMtxVar57 + 0x82) = 0;
    }
    ratio = (f32)(*(s16 *)((int)cameraMtxVar57 + 0x84) -
                  *(s16 *)((int)cameraMtxVar57 + 0x82)) /
            (f32)(s32)*(s16 *)((int)cameraMtxVar57 + 0x84);
    curve[0] = lbl_803E16AC;
    curve[1] = lbl_803E16A4;
    curve[2] = lbl_803E16AC;
    curve[3] = lbl_803E16AC;
    blend = Curve_EvalHermite(ratio,curve,(float *)0x0);
    cameraMtxVar57[0x23] =
         blend * (cameraMtxVar57[0x25] - cameraMtxVar57[0x24]) + cameraMtxVar57[0x24];
    cameraMtxVar57[0] =
         blend * (cameraMtxVar57[0xc] - cameraMtxVar57[0xb]) + cameraMtxVar57[0xb];
    cameraMtxVar57[1] =
         blend * (cameraMtxVar57[0xe] - cameraMtxVar57[0xd]) + cameraMtxVar57[0xd];
    cameraMtxVar57[2] =
         blend * (cameraMtxVar57[0x10] - cameraMtxVar57[0xf]) + cameraMtxVar57[0xf];
    cameraMtxVar57[3] =
         blend * (cameraMtxVar57[0x12] - cameraMtxVar57[0x11]) + cameraMtxVar57[0x11];
    cameraMtxVar57[4] =
         blend * (cameraMtxVar57[0x14] - cameraMtxVar57[0x13]) + cameraMtxVar57[0x13];
    cameraMtxVar57[5] =
         blend * (cameraMtxVar57[0x16] - cameraMtxVar57[0x15]) + cameraMtxVar57[0x15];
    cameraMtxVar57[6] =
         blend * (cameraMtxVar57[0x18] - cameraMtxVar57[0x17]) + cameraMtxVar57[0x17];
    cameraMtxVar57[7] =
         blend * (cameraMtxVar57[0x1a] - cameraMtxVar57[0x19]) + cameraMtxVar57[0x19];
    *(float *)(camera + 0xb4) =
         blend * (cameraMtxVar57[0x1c] - cameraMtxVar57[0x1b]) + cameraMtxVar57[0x1b];
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void doNothing_80103660(void) {}
