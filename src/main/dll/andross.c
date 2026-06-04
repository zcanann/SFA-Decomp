#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int andross_getExtraSize(void) { return 0xec; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int andross_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void andross_free(int obj)
{
    fn_8006CB24(obj);
    Rcp_DisableDistortionFilter();
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void andross_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void andross_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E74DC);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void andross_setPartSignal(int obj, int signal)
{
    int state;

    if ((void *)obj == NULL) {
        return;
    }
    state = *(int *)(obj + 0xb8);
    *(u8 *)(state + 0xad) |= signal;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int andross_updateModelAlpha(int obj)
{
    int state = *(int *)(obj + 0xb8);
    f32 v;
    f32 alpha;
    int model;
    int i;

    *(f32 *)(state + 0x68) = lbl_803E74D4;
    v = *(f32 *)(state + 0x68);
    model = *(int *)Obj_GetActiveModel(obj);
    alpha = lbl_803E74B4 * v;
    for (i = 0; i < *(u8 *)(model + 0xf8); i++) {
        *(s8 *)(ObjModel_GetRenderOp(model, i) + 0x43) = (int)alpha;
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void andross_init(int obj, u8 *setup)
{
    int state = *(int *)(obj + 0xb8);
    int i;
    int model;

    *(f32 *)(state + 0x58) = *(f32 *)(setup + 8);
    *(f32 *)(state + 0x5c) = *(f32 *)(setup + 0xc);
    *(f32 *)(state + 0x60) = *(f32 *)(setup + 0x10);
    *(s16 *)(state + 0x98) = 0;
    *(int *)(state + 0x88) = 0;
    *(int *)(state + 0x8c) = -1;
    *(f32 *)(state + 0x64) = lbl_803E7590;
    *(u8 *)(state + 0xb6) = 5;
    *(int *)(state + 0x7c) = 1;
    *(int *)(state + 0x80) = -1;
    *(s16 *)(state + 0xa0) = -0x8000;
    *(s16 *)obj = -0x8000;
    *(f32 *)(state + 0x6c) = lbl_803E7594;
    *(f32 *)(state + 0xa8) = lbl_803E74D4;
    *(f32 *)(state + 0x74) = lbl_803E7598;
    *(f32 *)(state + 0x78) = lbl_803E7530;
    *(u8 *)(state + 0xbc) = 1;
    ObjHits_SetTargetMask(obj, 4);
    *(void **)(obj + 0xbc) = (void *)andross_updateModelAlpha;
    fn_8006CB50();
    model = *(int *)Obj_GetActiveModel(obj);
    for (i = 0; i < *(u8 *)(model + 0xf8); i++) {
        *(u8 *)(ObjModel_GetRenderOp(model, i) + 0x43) = 0;
    }
    GameBit_Set(0xd, 0);
    unlockLevel(0, 0, 1);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8023A87C(int p1, int p2)
{
    void *spawned;

    spawned = *(void **)(p2 + 0x10);
    if (spawned != NULL) {
        *(f32 *)((char *)spawned + 0x14) -= lbl_803E74D8;
        *(int *)(p2 + 0x90) -= framesThisStep;
        if (*(int *)(p2 + 0x90) < 0) {
            fn_8022F558(*(int *)(p2 + 0x10), 5);
            *(int *)(p2 + 0x90) = 0;
            *(int *)(p2 + 0x10) = 0;
        }
    } else {
        f32 v = *(f32 *)(p2 + 0x6c);
        f32 zero = lbl_803E74D4;
        if (v >= zero) {
            *(f32 *)(p2 + 0x6c) = v - timeDelta;
            if (*(f32 *)(p2 + 0x6c) < zero)
                fn_80239DD8(p1, p2);
        } else if ((u32)GameBit_Get(0x12) != 0) {
            *(f32 *)(p2 + 0x6c) = (f32)(int)randomGetRange(1, 0x14);
            GameBit_Set(0x12, 0);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int fn_8023A6A4(int p1, f32 a, f32 b, f32 c)
{
    f32 val, ang;
    f32 dx, dy, dz, dist;
    int yaw;
    int result;
    f32 vel[3];

    result = 0;
    dx = *(f32 *)(p1 + 0xc0) - *(f32 *)(*(int *)p1 + 0xc);
    dy = *(f32 *)(p1 + 0xc4) - *(f32 *)(*(int *)p1 + 0x10);
    dz = *(f32 *)(p1 + 0xc8) - *(f32 *)(*(int *)p1 + 0x14);
    dist = sqrtf(dx * dx + dy * dy);
    yaw = (s16)getAngle(dx, dy);
    if ((s16)getAngle(dist, dz) > 0x2ee0 && dz > lbl_803DC4C0)
        result = 1;
    val = dist / b;
    if (val < -a)
        val = -a;
    else if (val > a)
        val = a;
    ang = lbl_803E74A0 * (f32)yaw / lbl_803E74A4;
    *(f32 *)(p1 + 0xd8) = val * fn_80293E80(ang);
    *(f32 *)(p1 + 0xdc) = val * sin(ang);
    fn_8022D48C((int)vel, *(int *)p1);
    *(f32 *)(p1 + 0xd8) -= vel[0] * lbl_803DC4C4;
    *(f32 *)(p1 + 0xdc) -= vel[1] * lbl_803DC4C4;
    *(f32 *)(p1 + 0xe0) = c;
    return result;
}
#pragma scheduling reset
#pragma peephole reset

extern f32 lbl_8032C098[];
extern f32 lbl_803DC440;
extern f32 lbl_803DC444;
extern f32 lbl_803DC448;
extern f32 lbl_803DC454;
extern f32 lbl_803DC458;
extern f32 lbl_803DC45C;
extern f32 lbl_803DC468;
extern f32 lbl_803DC470;
extern f32 lbl_803DC474;
extern f32 lbl_803DC478;
extern f32 lbl_803DC47C;
extern f32 lbl_803DC480;
extern f32 lbl_803DC488;
extern f32 lbl_803DC490;
extern f32 lbl_803DC494;
extern f32 lbl_803DC498;
extern f32 lbl_803DC49C;
extern f32 lbl_803DC4A0;
extern f32 lbl_803DC4A4;
extern f32 lbl_803DC4A8;
extern f32 lbl_803DC4AC;
extern f32 lbl_803DC4B0;
extern f32 lbl_803DC4B4;
extern f32 lbl_803DC4B8;
extern f32 lbl_803DC4D0;
extern f32 lbl_803DC4D4;
extern f32 lbl_803DDDB8;
extern f32 lbl_803E74B8;
extern f32 lbl_803E74BC;
extern f32 lbl_803E74C0;
extern f32 lbl_803E74C4;
extern f32 lbl_803E74C8;
extern f32 lbl_803E74CC;
extern f32 lbl_803E74D0;
extern f32 lbl_803E74E0;
extern f32 lbl_803E74E4;
extern f32 lbl_803E74E8;
extern f32 lbl_803E74EC;
extern f32 lbl_803E74F0;
extern f32 lbl_803E74F4;
extern f32 lbl_803E74F8;
extern f32 lbl_803E74FC;
extern f32 lbl_803E7500;
extern f32 lbl_803E7504;
extern f32 lbl_803E7508;
extern f32 lbl_803E750C;
extern f32 lbl_803E7510;
extern f32 lbl_803E7514;
extern f32 lbl_803E7518;
extern f32 lbl_803E751C;
extern f32 lbl_803E7520;
extern f32 lbl_803E7524;
extern f32 lbl_803E7528;
extern f32 lbl_803E752C;
extern f32 lbl_803E7534;
extern f32 lbl_803E7538;
extern f32 lbl_803E753C;
extern f32 lbl_803E7578;
extern f32 lbl_803E757C;
extern f32 lbl_803E7580;
extern f32 lbl_803E7584;
extern f64 lbl_803E7540;
extern f64 lbl_803E7548;
extern f64 lbl_803E7550;
extern f64 lbl_803E7558;
extern f64 lbl_803E7560;
extern f64 lbl_803E7568;
extern f64 lbl_803E7570;
extern int animatedObjGetSeqId(int obj);
extern int lbl_8032C088[];
extern f32 lbl_8032C09C[];
extern f32 lbl_8032C0A0[];
extern f32 lbl_8032C0A4[];
extern f32 lbl_8032C0A8[];
extern f32 lbl_8032C0C8[];
extern f32 lbl_8032C0CC[];
extern f32 lbl_8032C0D0[];
extern f32 lbl_8032C0D8[];
extern f32 lbl_8032C0DC[];
extern f32 lbl_8032C0E0[];
extern f32 lbl_8032C0E4[];
extern f32 lbl_8032C0E8[];
extern f32 lbl_8032C0EC[];
extern f32 lbl_8032C0F0[];
extern int lbl_803DC430;
extern int lbl_803DC434;
extern int lbl_803DC438;
extern int lbl_803DC43C;
extern int lbl_803DC44C;
extern int lbl_803DC450;
extern int lbl_803DC460;
extern int lbl_803DC464;
extern int lbl_803DC46C;
extern int lbl_803DC484;
extern int lbl_803DC48C;
extern int lbl_803DC4EC;
extern s16 lbl_803DC4BC;
extern s16 lbl_803DC4BE;
extern s16 lbl_803DDDC8;
extern s16 lbl_803DDDCA;
extern f32 lbl_803DC4CC;
extern void turnOnDistortionFilter(f32 *pos, f32 a, f32 *b, f32 c);
extern void fn_8022D460(int obj, f32 x);

typedef struct {
    u8 f80 : 1;
    u8 f40 : 1;
    u8 f20 : 1;
} AndrossFlagByte;

#pragma peephole off
#pragma scheduling off
void andross_update(int obj)

{
  int *piVar14;
  u8 stateChanged;
  u8 moveChanged;
  int iVar12;
  int iVar8;
  u32 uVar6;
  float fVar2;
  short sVar3;
  int iVar5;
  char cVar11;
  s16 uVar10;
  int *piVar7;
  int uVar9;
  u8 bVar13;
  f32 dVar16;
  f32 dVar17;
  f32 dVar18;
  f32 dVar19;
  float local_148;
  float local_144;
  float local_140;
  float local_13c;
  float local_138;
  float local_134;
  short local_130 [2];
  SunVec3 local_12c;
  SunVec3 local_120;
  SunVec3 local_114;
  SunVec3 local_108;
  SunVec3 local_fc;
  SunVec3 local_f0;
  SunVec3 local_e4;
  SunVec3 local_d8;
  SunVec3 local_cc;
  SunVec3 local_c0;
  SunVec3 local_b4;
  SunVec3 local_a8;
  SunVec3 local_9c;
  f32 local_90;
  f32 local_88;
  f32 local_80;
  f32 local_78;
  u32 uStack100;
  f32 local_50;
    piVar14 = *(int **)(obj + 0xb8);
  moveChanged = 0;
  stateChanged = 0;
  iVar12 = 0;
  if (*(u8 *)((int)piVar14 + 0xb6) != 0) {
    *(u8 *)((int)piVar14 + 0xb6) -= 1;
    goto LAB_8023ef14;
  }
  if (*(void **)(piVar14 + 1) == NULL) {
    iVar5 = ObjList_FindObjectById(0x47b78);
    piVar14[1] = iVar5;
  }
  if (*(void **)(piVar14 + 2) == NULL) {
    iVar5 = ObjList_FindObjectById(0x47b6a);
    piVar14[2] = iVar5;
  }
  if (*(void **)(piVar14 + 3) == NULL) {
    iVar5 = ObjList_FindObjectById(0x47dd9);
    piVar14[3] = iVar5;
  }
  if (*piVar14 == 0) {
    iVar5 = getArwing();
    *piVar14 = iVar5;
    if (*piVar14 == 0) goto LAB_8023ef14;
    *(f32 *)(piVar14 + 0x1c) = *(f32 *)(*piVar14 + 0x14);
        fn_8022D460(*piVar14,(f32)lbl_803DC438);
  }
  for (iVar8 = 0; (u8)iVar8 < 4; iVar8 = iVar8 + 1) {
    uVar6 = (u8)iVar8;
    if (*(void **)((int)piVar14 + uVar6 * 4 + 0x18) == NULL) {
      *(int *)((int)piVar14 + uVar6 * 4 + 0x18) = ObjList_FindObjectById(lbl_8032C088[uVar6]);
      if (*(void **)((int)piVar14 + uVar6 * 4 + 0x18) != NULL) {
        *(f32 *)(piVar14 + uVar6 * 3 + 10) = *(float *)(*(int *)((int)piVar14 + uVar6 * 4 + 0x18) + 0xc) - *(float *)(obj + 0xc);
        *(f32 *)(piVar14 + uVar6 * 3 + 0xb) = *(float *)(*(int *)((int)piVar14 + uVar6 * 4 + 0x18) + 0x10) - *(float *)(obj + 0x10);
        *(f32 *)(piVar14 + uVar6 * 3 + 0xc) = *(float *)(*(int *)((int)piVar14 + uVar6 * 4 + 0x18) + 0x14) - *(float *)(obj + 0x14);
      }
    }
    else {
      *(float *)(*(int *)((int)piVar14 + uVar6 * 4 + 0x18) + 0xc) = *(float *)(obj + 0xc) + *(f32 *)(piVar14 + uVar6 * 3 + 10)
      ;
      *(float *)(*(int *)((int)piVar14 + uVar6 * 4 + 0x18) + 0x10) =
           *(float *)(obj + 0x10) + *(f32 *)(piVar14 + uVar6 * 3 + 0xb);
      *(float *)(*(int *)((int)piVar14 + uVar6 * 4 + 0x18) + 0x14) =
           *(float *)(obj + 0x14) + *(f32 *)(piVar14 + uVar6 * 3 + 0xc);
    }
  }
  iVar5 = piVar14[0x1f];
  if (iVar5 != piVar14[0x20]) {
    stateChanged = 1;
  }
  piVar14[0x20] = iVar5;
  fVar2 = lbl_803E74D4;
  *(f32 *)(piVar14 + 0x36) = lbl_803E74D4;
  *(f32 *)(piVar14 + 0x37) = fVar2;
  *(f32 *)(piVar14 + 0x38) = fVar2;
  if ((-0x4000 < *(short *)(piVar14 + 0x28)) && (*(s16 *)obj < 0x4000)) {
    iVar12 = 1;
  }
  ObjPath_GetPointWorldPosition(obj,iVar12,(f32 *)(piVar14 + 0x30),(f32 *)(piVar14 + 0x31),(f32 *)(piVar14 + 0x32),0);
  fVar2 = lbl_803E74E0;
  if (iVar12 == 1) {
    *(f32 *)(piVar14 + 0x31) = *(f32 *)(piVar14 + 0x31) + lbl_803E74E0;
    *(f32 *)(piVar14 + 0x32) = *(f32 *)(piVar14 + 0x32) + fVar2;
  }
  switch (piVar14[0x1f]) {
  case 1:
        if (stateChanged) {
          if (*(char *)(piVar14 + 0x2f) == '\0') {
            androsshand_setState(piVar14[1],2,1);
            androsshand_setState(piVar14[2],2,1);
          }
          else {
            *(undefined *)(piVar14 + 0x2f) = 0;
          }
          *(undefined *)((int)piVar14 + 0xae) = 10;
          *(undefined *)((int)piVar14 + 0xaf) = 10;
          *(undefined *)(piVar14 + 0x2c) = 10;
        }
        if (piVar14[0x21] != 0) {
          iVar12 = piVar14[0x22];
          if (iVar12 == 3) {
LAB_8023ad84:
            piVar14[0x22] = 0;
          }
          else if (iVar12 < 3) {
            if (iVar12 != 0) goto LAB_8023ad84;
            piVar14[0x22] = 1;
          }
          else {
            if (((iVar12 == 0x17) || (0x16 < iVar12)) || (iVar12 < 0x16)) goto LAB_8023ad84;
            if (*(char *)(piVar14 + 0x2e) == '\0') {
              piVar14[0x22] = 0;
            }
            else {
              piVar14[0x22] = 0x17;
            }
          }
          piVar14[0x21] = 0;
        }
    break;
  case 2:
      if ((stateChanged) &&
         (*(u8 *)((int)piVar14 + 0xad) = *(u8 *)((int)piVar14 + 0xad) & 0xf9,
         piVar14[0x22] == 0x16)) {
        androsshand_setState(piVar14[1],1,1);
        androsshand_setState(piVar14[2],1,1);
      }
      if (piVar14[0x21] != 0) {
        switch(piVar14[0x22]) {
        default:
          piVar14[0x22] = 6;
          break;
        case 6:
          piVar14[0x22] = 7;
          break;
        case 7:
          piVar14[0x22] = 10;
          break;
        case 10:
          piVar14[0x22] = 0x12;
          break;
        case 0x14:
          piVar14[0x22] = 0xb;
          break;
        case 0x11:
          piVar14[0x22] = 0x16;
          *(s16 *)(piVar14 + 0x28) = 0x8000;
          piVar14[0x1f] = piVar14[0x1f] + -1;
        }
        piVar14[0x21] = 0;
      }
    break;
  case 3:
      if (stateChanged) {
        *(undefined *)((int)piVar14 + 0xae) = 0xf;
        *(undefined *)((int)piVar14 + 0xaf) = 0xf;
        *(undefined *)(piVar14 + 0x2c) = 0xf;
        piVar14[0x22] = 0;
        *(undefined *)((int)piVar14 + 0xb7) = 0;
      }
      if (piVar14[0x21] != 0) {
        iVar12 = piVar14[0x22];
        if (iVar12 == 3) {
          piVar14[0x22] = 4;
        }
        else if ((iVar12 < 3) || (4 < iVar12)) {
          piVar14[0x22] = 1;
        }
        else {
          *(char *)((int)piVar14 + 0xb7) = *(char *)((int)piVar14 + 0xb7) + '\x01';
          if (*(u8 *)((int)piVar14 + 0xb7) < 4) {
            piVar14[0x22] = 0;
          }
          else {
            piVar14[0x1f] = piVar14[0x1f] + -1;
            piVar14[0x22] = 0x16;
            *(s16 *)(piVar14 + 0x28) = 0;
          }
        }
        piVar14[0x21] = 0;
      }
    break;
  case 4:
    if (piVar14[0x21] != 0) {
      switch(piVar14[0x22]) {
      default:
        piVar14[0x22] = 6;
        break;
      case 6:
        piVar14[0x22] = 7;
        break;
      case 7:
        piVar14[0x22] = 10;
        break;
      case 10:
        piVar14[0x22] = 0x12;
        break;
      case 0x14:
        piVar14[0x22] = 0xb;
        break;
      case 0xf:
        piVar14[0x22] = 9;
        break;
      case 9:
        piVar14[0x22] = 8;
        break;
      case 0x11:
        piVar14[0x22] = 0x18;
      }
      piVar14[0x21] = 0;
    }
    break;
  case 5:
    if (stateChanged) {
      piVar14[0x22] = 0xd;
      *(undefined *)(piVar14 + 0x2b) = 0;
    }
    if (piVar14[0x21] != 0) {
      switch(piVar14[0x22]) {
      default:
        *(undefined *)((int)piVar14 + 0xb1) = 3;
      case 0xf:
        piVar14[0x22] = 0x12;
        *(undefined *)(piVar14 + 0x2b) = 0;
        break;
      case 0x14:
        if (*(char *)(piVar14 + 0x2b) == '\x01') {
          piVar14[0x22] = 0xb;
        }
        else if (*(char *)(piVar14 + 0x2b) == '\0') {
          piVar14[0x22] = 0x15;
        }
        *(u8 *)(piVar14 + 0x2b) = *(u8 *)(piVar14 + 0x2b) ^ 1;
        break;
      case 0x15:
        piVar14[0x22] = 0x12;
        break;
      case 0x11:
        piVar14[0x22] = 0x18;
        break;
      case 0x19:
        piVar14[0x1f] = 6;
        break;
      case 0x1a:
        piVar14[0x22] = 0x1b;
      }
      piVar14[0x21] = 0;
    }
    break;
  case 6:
    if (stateChanged) {
      piVar14[0x22] = 0x1c;
      *(undefined *)(piVar14 + 0x2b) = 0;
    }
    break;
  }
  iVar5 = piVar14[0x22];
  if (iVar5 != piVar14[0x23]) {
    moveChanged = 1;
  }
  piVar14[0x23] = iVar5;
  switch(piVar14[0x22]) {
  case 0:
    if (moveChanged) {
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,0,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C098[0];
      if (piVar14[0x1f] == 1) {
        *(f32 *)(piVar14 + 0x27) = lbl_803E74E4;
      }
      else {
        *(f32 *)(piVar14 + 0x27) = lbl_803E74E8;
      }
    }
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar19 = lbl_803E74EC;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, lbl_803E74F0 < dVar17)) {
      dVar19 = lbl_803E74F0;
    }
    dVar17 = lbl_803E74F4;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, lbl_803E74F8 < dVar16)) {
      dVar17 = lbl_803E74F8;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74CC * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E74FC * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    *(f32 *)(piVar14 + 0x27) = *(f32 *)(piVar14 + 0x27) - timeDelta;
    if (*(f32 *)(piVar14 + 0x27) < lbl_803E74D4) {
      piVar14[0x21] = 1;
    }
    if ((u32)*(u8 *)((int)piVar14 + 0xae) + (u32)*(u8 *)((int)piVar14 + 0xaf) +
        (u32)*(u8 *)(piVar14 + 0x2c) == 0) {
      piVar14[0x1f] = piVar14[0x1f] + 1;
      piVar14[0x22] = 5;
      piVar14[0x21] = 0;
      GameBit_Set(0xd,0);
    }
    break;
  case 1:
    if (moveChanged) {
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,0xc,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C0C8[0];
    }
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar19 = lbl_803E74EC;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, lbl_803E74F0 < dVar17)) {
      dVar19 = lbl_803E74F0;
    }
    dVar17 = lbl_803E74F4;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, lbl_803E74F8 < dVar16)) {
      dVar17 = lbl_803E74F8;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74CC * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E74FC * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    if (lbl_803E74DC <= *(float *)(obj + 0x98)) {
      piVar14[0x22] = 2;
      piVar14[0x21] = 0;
    }
    if ((u32)*(u8 *)((int)piVar14 + 0xae) + (u32)*(u8 *)((int)piVar14 + 0xaf) +
        (u32)*(u8 *)(piVar14 + 0x2c) == 0) {
      piVar14[0x1f] = piVar14[0x1f] + 1;
      piVar14[0x22] = 5;
      piVar14[0x21] = 0;
      GameBit_Set(0xd,0);
    }
    break;
  case 2:
    if (moveChanged) {
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,0xe,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C0D0[0];
      *(f32 *)(piVar14 + 0x27) = lbl_803E74F0;
      *(s16 *)(piVar14 + 0x26) = 0xffff;
    }
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar19 = lbl_803E74EC;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, lbl_803E74F0 < dVar17)) {
      dVar19 = lbl_803E74F0;
    }
    dVar17 = lbl_803E74F4;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, lbl_803E74F8 < dVar16)) {
      dVar17 = lbl_803E74F8;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74CC * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E74FC * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    Sfx_KeepAliveLoopedObjectSound(obj,0x467);
    *(u16 *)(piVar14 + 0x26) = *(short *)(piVar14 + 0x26) - (u16)framesThisStep;
    if (*(short *)(piVar14 + 0x26) < 0) {
      fn_8023A268(obj,(int)piVar14,0);
      *(short *)(piVar14 + 0x26) = (short)lbl_803DC43C;
    }
    *(f32 *)(piVar14 + 0x27) = *(f32 *)(piVar14 + 0x27) - timeDelta;
    if (*(f32 *)(piVar14 + 0x27) < lbl_803E74D4) {
      piVar14[0x22] = 3;
      piVar14[0x21] = 0;
    }
    if ((u32)*(u8 *)((int)piVar14 + 0xae) + (u32)*(u8 *)((int)piVar14 + 0xaf) +
        (u32)*(u8 *)(piVar14 + 0x2c) == 0) {
      piVar14[0x1f] = piVar14[0x1f] + 1;
      piVar14[0x22] = 5;
      piVar14[0x21] = 0;
      GameBit_Set(0xd,0);
    }
    break;
  case 3:
    if (moveChanged) {
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,0xd,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C0CC[0];
    }
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar19 = lbl_803E74EC;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, lbl_803E74F0 < dVar17)) {
      dVar19 = lbl_803E74F0;
    }
    dVar17 = lbl_803E7500;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, lbl_803E74CC < dVar16)) {
      dVar17 = lbl_803E74CC;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74CC * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E74FC * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    if (lbl_803E74DC <= *(float *)(obj + 0x98)) {
      piVar14[0x21] = 1;
    }
    break;
  case 4:
    if (moveChanged) {
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,0,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C098[0];
      GameBit_Set(0xd,1);
      *(f32 *)(piVar14 + 0x27) = lbl_803E7504;
    }
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar19 = lbl_803E74EC;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, lbl_803E74F0 < dVar17)) {
      dVar19 = lbl_803E74F0;
    }
    dVar17 = lbl_803E7500;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, lbl_803E74CC < dVar16)) {
      dVar17 = lbl_803E74CC;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74CC * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E74FC * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    *(f32 *)(piVar14 + 0x27) = *(f32 *)(piVar14 + 0x27) - timeDelta;
    if (*(f32 *)(piVar14 + 0x27) < lbl_803E74D4) {
      piVar14[0x21] = 1;
      GameBit_Set(0xd,0);
    }
    if ((u32)*(u8 *)((int)piVar14 + 0xae) + (u32)*(u8 *)((int)piVar14 + 0xaf) +
        (u32)*(u8 *)(piVar14 + 0x2c) == 0) {
      piVar14[0x1f] = piVar14[0x1f] + 1;
      piVar14[0x22] = 5;
      piVar14[0x21] = 0;
      GameBit_Set(0xd,0);
    }
    break;
  case 0x15:
    if (moveChanged) {
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,0,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C098[0];
      GameBit_Set(0xd,1);
      *(f32 *)(piVar14 + 0x27) = lbl_803E7504;
    }
    for (iVar12 = 0; (u8)iVar12 < 6; iVar12 = iVar12 + 1) {
      if ((u32)GameBit_Get((u8)iVar12 + 0x108) != 0) {
        *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
        goto LAB_8023bb18;
      }
    }
    *(u16 *)((int)piVar14 + 0xa6) = *(short *)((int)piVar14 + 0xa6) - (u16)framesThisStep;
    if (*(short *)((int)piVar14 + 0xa6) < 1) {
      iVar12 = randomGetRange(0,5);
      GameBit_Set(iVar12 + 0x108,1);
      *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
    }
LAB_8023bb18:
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar19 = lbl_803E74EC;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, lbl_803E74F0 < dVar17)) {
      dVar19 = lbl_803E74F0;
    }
    dVar17 = lbl_803E7500;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, lbl_803E74CC < dVar16)) {
      dVar17 = lbl_803E74CC;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74CC * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E74FC * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    *(f32 *)(piVar14 + 0x27) = *(f32 *)(piVar14 + 0x27) - timeDelta;
    if (*(f32 *)(piVar14 + 0x27) < lbl_803E74D4) {
      piVar14[0x21] = 1;
      GameBit_Set(0xd,0);
    }
    break;
  case 6:
    if (moveChanged) {
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,0,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C098[0];
      androsshand_setState(piVar14[2],4,0);
    }
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar19 = lbl_803E7508;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, lbl_803E750C < dVar17)) {
      dVar19 = lbl_803E750C;
    }
    dVar17 = lbl_803E74F4;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, lbl_803E74F8 < dVar16)) {
      dVar17 = lbl_803E74F8;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74E8 * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E74FC * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    bVar13 = *(u8 *)(*(int *)(obj + 0xb8) + 0xad);
    if ((bVar13 & 1) != 0) {
      *(u8 *)(*(int *)(obj + 0xb8) + 0xad) = bVar13 & 0xfe;
      piVar14[0x21] = 1;
    }
    break;
  case 7:
    if (moveChanged) {
      androsshand_setState(piVar14[1],4,0);
    }
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar19 = lbl_803E7508;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, lbl_803E750C < dVar17)) {
      dVar19 = lbl_803E750C;
    }
    dVar17 = lbl_803E74F4;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, lbl_803E74F8 < dVar16)) {
      dVar17 = lbl_803E74F8;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74E8 * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E74FC * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    bVar13 = *(u8 *)(*(int *)(obj + 0xb8) + 0xad);
    if ((bVar13 & 1) != 0) {
      *(u8 *)(*(int *)(obj + 0xb8) + 0xad) = bVar13 & 0xfe;
      piVar14[0x21] = 1;
    }
    break;
  case 9:
    if (moveChanged) {
      androsshand_setState(piVar14[1],6,0);
    }
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar19 = lbl_803E74EC;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, lbl_803E74F0 < dVar17)) {
      dVar19 = lbl_803E74F0;
    }
    dVar17 = lbl_803E7500;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, lbl_803E74CC < dVar16)) {
      dVar17 = lbl_803E74CC;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74CC * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E74FC * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    bVar13 = *(u8 *)(*(int *)(obj + 0xb8) + 0xad);
    if ((bVar13 & 1) != 0) {
      *(u8 *)(*(int *)(obj + 0xb8) + 0xad) = bVar13 & 0xfe;
      piVar14[0x21] = 1;
    }
    break;
  case 8:
    if (moveChanged) {
      androsshand_setState(piVar14[2],6,0);
    }
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar19 = lbl_803E74EC;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, lbl_803E74F0 < dVar17)) {
      dVar19 = lbl_803E74F0;
    }
    dVar17 = lbl_803E7500;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, lbl_803E74CC < dVar16)) {
      dVar17 = lbl_803E74CC;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74CC * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E74FC * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    bVar13 = *(u8 *)(*(int *)(obj + 0xb8) + 0xad);
    if ((bVar13 & 1) != 0) {
      *(u8 *)(*(int *)(obj + 0xb8) + 0xad) = bVar13 & 0xfe;
      piVar14[0x21] = 1;
    }
    break;
  case 10:
    if ((*(u8 *)((int)piVar14 + 0xad) & 6) == 6) {
      piVar14[0x1f] = piVar14[0x1f] + 1;
      if (piVar14[0x1f] < 5) {
        iVar12 = randomGetRange(0,1);
        if (iVar12 == 0) {
          uVar9 = 0x472;
        }
        else {
          uVar9 = 0x471;
        }
        Sfx_PlayFromObject(obj,uVar9);
        piVar14[0x22] = 0x16;
        *(s16 *)(piVar14 + 0x28) = 0x8000;
      }
    }
    else {
      lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
      lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
      dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
      dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
      dVar19 = lbl_803E7508;
      if ((dVar19 <= dVar17) && (dVar19 = dVar17, lbl_803E750C < dVar17)) {
        dVar19 = lbl_803E750C;
      }
      dVar17 = lbl_803E74F4;
      if ((dVar17 <= dVar16) && (dVar17 = dVar16, lbl_803E74F8 < dVar16)) {
        dVar17 = lbl_803E74F8;
      }
            dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA))
                                            / lbl_803E74A4));
      *(f32 *)(piVar14 + 0x33) = (lbl_803E74E8 * dVar16 +
                       (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
            dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8))
                                            / lbl_803E74A4));
      *(f32 *)(piVar14 + 0x34) = (lbl_803E74FC * dVar19 +
                       (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
      piVar14[0x35] = piVar14[0x18];
      if (moveChanged) {
        androsshand_setState(piVar14[1],5,0);
        androsshand_setState(piVar14[2],5,0);
      }
      bVar13 = *(u8 *)(*(int *)(obj + 0xb8) + 0xad);
      if ((bVar13 & 1) != 0) {
        *(u8 *)(*(int *)(obj + 0xb8) + 0xad) = bVar13 & 0xfe;
        piVar14[0x21] = 1;
      }
    }
    break;
  case 0xb:
  case 0xd:
    if (moveChanged) {
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,1,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C09C[0];
      if (piVar14[0x1f] < 5) {
        androsshand_setState(piVar14[1],0,0);
        androsshand_setState(piVar14[2],0,0);
      }
      else {
        androsshand_setState(piVar14[1],9,1);
        androsshand_setState(piVar14[2],9,1);
        *(u8 *)((int)piVar14 + 0xad) = *(u8 *)((int)piVar14 + 0xad) | 6;
      }
    }
    if ((piVar14[0x1f] == 5) && (piVar14[0x22] == 0xb)) {
      for (iVar12 = 0; (u8)iVar12 < 6; iVar12 = iVar12 + 1) {
        if ((u32)GameBit_Get((u8)iVar12 + 0x108) != 0) {
          *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
          goto LAB_8023c584;
        }
      }
      *(u16 *)((int)piVar14 + 0xa6) = *(short *)((int)piVar14 + 0xa6) - (u16)framesThisStep;
      if (*(short *)((int)piVar14 + 0xa6) < 1) {
        iVar12 = randomGetRange(0,5);
        GameBit_Set(iVar12 + 0x108,1);
        *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
      }
    }
LAB_8023c584:
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar19 = lbl_803E7510;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, lbl_803E74FC < dVar17)) {
      dVar19 = lbl_803E74FC;
    }
    dVar17 = lbl_803E74F4;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, lbl_803E74F8 < dVar16)) {
      dVar17 = lbl_803E74F8;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74FC * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E7514 * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    if (lbl_803E74DC <= *(float *)(obj + 0x98)) {
      iVar12 = piVar14[0x22];
      if (((iVar12 == 0xc) || (iVar12 < 0xc)) || (0xd < iVar12)) {
        piVar14[0x22] = 0xc;
      }
      else {
        piVar14[0x22] = 0xe;
      }
    }
    fVar2 = lbl_803E74B8 * *(float *)(obj + 0x98);
    if (lbl_803E74B8 <= fVar2) {
      dVar19 = lbl_803E74CC;
    }
    else {
      dVar19 = -(lbl_803E74C0 * lbl_803E74C4 * fVar2 - lbl_803E74BC);
      if (fVar2 < lbl_803E74C8) {
        lbl_803DDDB8 = lbl_803DC4D4;
      }
    }
    lbl_803DDDB8 = lbl_803DDDB8 + lbl_803DC4D0;
    if (lbl_803E74D0 < lbl_803DDDB8) {
      lbl_803DDDB8 = lbl_803DDDB8 - lbl_803E74D0;
    }
    turnOnDistortionFilter((f32 *)(piVar14 + 0x30),dVar19,&lbl_803DC4CC,lbl_803DDDB8);
    break;
  case 0xe:
    fVar2 = lbl_803E74B8 * *(float *)(obj + 0x98) + lbl_803E74B8;
    if (lbl_803E74B8 <= fVar2) {
      dVar19 = lbl_803E74CC;
    }
    else {
      dVar19 = -(lbl_803E74C0 * lbl_803E74C4 * fVar2 - lbl_803E74BC);
      if (fVar2 < lbl_803E74C8) {
        lbl_803DDDB8 = lbl_803DC4D4;
      }
    }
    lbl_803DDDB8 = lbl_803DDDB8 + lbl_803DC4D0;
    if (lbl_803E74D0 < lbl_803DDDB8) {
      lbl_803DDDB8 = lbl_803DDDB8 - lbl_803E74D0;
    }
    turnOnDistortionFilter((f32 *)(piVar14 + 0x30),dVar19,&lbl_803DC4CC,lbl_803DDDB8);
    if (moveChanged) {
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,2,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C0A0[0];
      *(undefined *)((int)piVar14 + 0xb1) = 0;
      GameBit_Set(0x10,0);
      *(short *)(piVar14 + 0x26) = (short)lbl_803DC44C;
      *(f32 *)(piVar14 + 0x27) = lbl_803E74D4;
    }
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar19 = lbl_803E74EC;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, lbl_803E74F0 < dVar17)) {
      dVar19 = lbl_803E74F0;
    }
    dVar17 = lbl_803E7508;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, lbl_803E750C < dVar16)) {
      dVar17 = lbl_803E750C;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74FC * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E7514 * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    fn_8023A6A4((int)piVar14,lbl_803DC440,lbl_803DC444,lbl_803DC448);
    Sfx_KeepAliveLoopedObjectSound(obj,0x466);
    if ((*(short *)(piVar14 + 0x26) != 0) &&
       (*(u16 *)(piVar14 + 0x26) = *(short *)(piVar14 + 0x26) - (u16)framesThisStep,
       *(short *)(piVar14 + 0x26) < 1)) {
      *(s16 *)(piVar14 + 0x26) = 0;
      GameBit_Set(0xf,1);
    }
    *(f32 *)(piVar14 + 0x27) = *(f32 *)(piVar14 + 0x27) - timeDelta;
    if (*(f32 *)(piVar14 + 0x27) < lbl_803E74D4) {
      fn_80239FCC(obj,(int)piVar14);
            *(f32 *)(piVar14 + 0x27) = *(f32 *)(piVar14 + 0x27) + (f32)(lbl_803DC450);
    }
    fn_80239EAC(obj,(int)piVar14);
    iVar12 = GameBit_Get(0x10);
    if (iVar12 != 0) {
      GameBit_Set(0x10,0);
      piVar14[0x22] = 0x1a;
      lbl_803DDDB8 = lbl_803DC4D4 + lbl_803DC4D0;
      if (lbl_803E74D0 < lbl_803DDDB8) {
        lbl_803DDDB8 = lbl_803DDDB8 - lbl_803E74D0;
      }
      turnOnDistortionFilter((f32 *)(piVar14 + 0x30),lbl_803E74BC,&lbl_803DC4CC,lbl_803DDDB8);
      Rcp_DisableDistortionFilter();
    }
    break;
  case 0xc:
    fVar2 = lbl_803E74B8 * *(float *)(obj + 0x98) + lbl_803E74B8;
    if (lbl_803E74B8 <= fVar2) {
      dVar19 = lbl_803E74CC;
    }
    else {
      dVar19 = -(lbl_803E74C0 * lbl_803E74C4 * fVar2 - lbl_803E74BC);
      if (fVar2 < lbl_803E74C8) {
        lbl_803DDDB8 = lbl_803DC4D4;
      }
    }
    lbl_803DDDB8 = lbl_803DDDB8 + lbl_803DC4D0;
    if (lbl_803E74D0 < lbl_803DDDB8) {
      lbl_803DDDB8 = lbl_803DDDB8 - lbl_803E74D0;
    }
    turnOnDistortionFilter((f32 *)(piVar14 + 0x30),dVar19,&lbl_803DC4CC,lbl_803DDDB8);
    if (moveChanged) {
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,2,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C0A0[0];
      if (piVar14[0x1f] < 5) {
        *(undefined *)((int)piVar14 + 0xb1) = 1;
      }
      *(short *)(piVar14 + 0x26) = (short)lbl_803DC460;
      *(f32 *)(piVar14 + 0x27) = lbl_803E74D4;
    }
    Sfx_KeepAliveLoopedObjectSound(obj,0x466);
    if (piVar14[0x1f] == 5) {
      for (iVar12 = 0; (u8)iVar12 < 6; iVar12 = iVar12 + 1) {
        if ((u32)GameBit_Get((u8)iVar12 + 0x108) != 0) {
          *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
          goto LAB_8023cbdc;
        }
      }
      *(u16 *)((int)piVar14 + 0xa6) = *(short *)((int)piVar14 + 0xa6) - (u16)framesThisStep;
      if (*(short *)((int)piVar14 + 0xa6) < 1) {
        iVar12 = randomGetRange(0,5);
        GameBit_Set(iVar12 + 0x108,1);
        *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
      }
    }
LAB_8023cbdc:
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar19 = lbl_803E74F4;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, lbl_803E74F8 < dVar17)) {
      dVar19 = lbl_803E74F8;
    }
    dVar17 = lbl_803E7510;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, lbl_803E74FC < dVar16)) {
      dVar17 = lbl_803E74FC;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74FC * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E7514 * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    cVar11 = fn_8023A6A4((int)piVar14,lbl_803DC454,lbl_803DC458,lbl_803DC45C);
    if (cVar11 != '\0') {
      piVar14[0x22] = 0xf;
      lbl_803DDDB8 = lbl_803DC4D4 + lbl_803DC4D0;
      if (lbl_803E74D0 < lbl_803DDDB8) {
        lbl_803DDDB8 = lbl_803DDDB8 - lbl_803E74D0;
      }
      turnOnDistortionFilter((f32 *)(piVar14 + 0x30),lbl_803E74BC,&lbl_803DC4CC,lbl_803DDDB8);
      Rcp_DisableDistortionFilter();
    }
    *(f32 *)(piVar14 + 0x27) = *(f32 *)(piVar14 + 0x27) - timeDelta;
    if (*(f32 *)(piVar14 + 0x27) < lbl_803E74D4) {
      fn_80239FCC(obj,(int)piVar14);
            *(f32 *)(piVar14 + 0x27) = *(f32 *)(piVar14 + 0x27) + (f32)(lbl_803DC464);
    }
    fn_80239EAC(obj,(int)piVar14);
    if (*(char *)((int)piVar14 + 0xb5) == '\0') {
      if (*(f32 *)(piVar14 + 0x32) < *(float *)(*piVar14 + 0x14)) {
        piVar14[0x22] = 0x10;
        *(undefined *)(piVar14 + 0x2e) = 1;
        *(int *)(*piVar14 + 0x14) = piVar14[0x32];
        *(f32 *)(piVar14 + 0x38) = lbl_803E74D4;
        lbl_803DDDB8 = lbl_803DC4D4 + lbl_803DC4D0;
        if (lbl_803E74D0 < lbl_803DDDB8) {
          lbl_803DDDB8 = lbl_803DDDB8 - lbl_803E74D0;
        }
        turnOnDistortionFilter((f32 *)(piVar14 + 0x30),lbl_803E74BC,&lbl_803DC4CC,lbl_803DDDB8);
        Rcp_DisableDistortionFilter();
        break;
      }
    }
    else {
      if (piVar14[0x1f] == 5) {
        piVar14[0x22] = 0x19;
      }
      else {
        piVar14[0x22] = 0xf;
      }
      lbl_803DDDB8 = lbl_803DC4D4 + lbl_803DC4D0;
      if (lbl_803E74D0 < lbl_803DDDB8) {
        lbl_803DDDB8 = lbl_803DDDB8 - lbl_803E74D0;
      }
      turnOnDistortionFilter((f32 *)(piVar14 + 0x30),lbl_803E74BC,&lbl_803DC4CC,lbl_803DDDB8);
      Rcp_DisableDistortionFilter();
    }
    *(u16 *)(piVar14 + 0x26) = *(short *)(piVar14 + 0x26) - (u16)framesThisStep;
    if (*(short *)(piVar14 + 0x26) < 0) {
      piVar14[0x22] = 0xf;
      lbl_803DDDB8 = lbl_803DC4D4 + lbl_803DC4D0;
      if (lbl_803E74D0 < lbl_803DDDB8) {
        lbl_803DDDB8 = lbl_803DDDB8 - lbl_803E74D0;
      }
      turnOnDistortionFilter((f32 *)(piVar14 + 0x30),lbl_803E74BC,&lbl_803DC4CC,lbl_803DDDB8);
      Rcp_DisableDistortionFilter();
    }
    break;
  case 0xf:
    if (moveChanged) {
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,0x10,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C0D8[0];
    }
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar19 = lbl_803E7500;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, lbl_803E74CC < dVar17)) {
      dVar19 = lbl_803E74CC;
    }
    dVar17 = lbl_803E74F4;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, lbl_803E74F8 < dVar16)) {
      dVar17 = lbl_803E74F8;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74E8 * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E74FC * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    if (lbl_803E74DC <= *(float *)(obj + 0x98)) {
      piVar14[0x21] = 1;
    }
    break;
  case 0x10:
    if (moveChanged) {
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,0x10,lbl_803E74D4,0);
      *(float *)(iVar12 + 100) = lbl_803E7518;
    }
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar18 = lbl_803E74D4;
    dVar19 = dVar18;
    if ((dVar18 <= dVar17) && (dVar19 = dVar17, dVar18 < dVar17)) {
      dVar19 = dVar18;
    }
    dVar18 = lbl_803E74D4;
    dVar17 = dVar18;
    if ((dVar18 <= dVar16) && (dVar17 = dVar16, dVar18 < dVar16)) {
      dVar17 = dVar18;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74D4 * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E74D4 * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    iVar12 = *piVar14;
    local_e4.x = (*(f32 *)(piVar14 + 0x30) - *(float *)(iVar12 + 0xc)) * lbl_803DC468;
    local_e4.y = (*(f32 *)(piVar14 + 0x31) - *(float *)(iVar12 + 0x10)) * lbl_803DC468;
    local_e4.z = (*(f32 *)(piVar14 + 0x32) - *(float *)(iVar12 + 0x14)) * lbl_803DC468;
    local_d8 = local_e4;
    fn_8022D4AC(iVar12,(int)&local_d8);
    fVar2 = -(lbl_803E74B0 * timeDelta - *(f32 *)(piVar14 + 0x2a));
    if (fVar2 < lbl_803E74EC) {
      fVar2 = lbl_803E74EC;
    }
    *(f32 *)(piVar14 + 0x2a) = fVar2;
    if (lbl_803E74DC <= *(float *)(obj + 0x98)) {
      *(u16 *)(*piVar14 + 6) = *(u16 *)(*piVar14 + 6) | 0x4000;
      piVar14[0x22] = 0x11;
    }
    break;
  case 0x11:
    if (moveChanged) {
      Sfx_PlayFromObject(obj,0x468);
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,0x15,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C0EC[0];
      arwarwing_addShield(*piVar14,0xfffffffc);
    }
    fVar2 = -(lbl_803E74B0 * timeDelta - *(f32 *)(piVar14 + 0x2a));
    if (fVar2 < lbl_803E74EC) {
      fVar2 = lbl_803E74EC;
    }
    *(f32 *)(piVar14 + 0x2a) = fVar2;
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar18 = lbl_803E74D4;
    dVar19 = dVar18;
    if ((dVar18 <= dVar17) && (dVar19 = dVar17, dVar18 < dVar17)) {
      dVar19 = dVar18;
    }
    dVar18 = lbl_803E74D4;
    dVar17 = dVar18;
    if ((dVar18 <= dVar16) && (dVar17 = dVar16, dVar18 < dVar16)) {
      dVar17 = dVar18;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74D4 * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E74D4 * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    if (lbl_803E74DC <= *(float *)(obj + 0x98)) {
      piVar14[0x21] = 1;
    }
    break;
  case 0x12:
    if (moveChanged) {
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,0x12,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C0E0[0];
      androsshand_setState(piVar14[1],0,0);
      androsshand_setState(piVar14[2],0,0);
      if ((piVar14[0x1f] == 5) && (*(char *)(piVar14 + 0x2b) != '\0')) {
        GameBit_Set(0xe,1);
      }
    }
    *(f32 *)(piVar14 + 0x1a) = *(f32 *)(piVar14 + 0x1a) - lbl_803E751C;
    fVar2 = *(f32 *)(piVar14 + 0x1a);
    if (fVar2 < lbl_803E74D4) {
      fVar2 = lbl_803E74D4;
    }
    *(f32 *)(piVar14 + 0x1a) = fVar2;
    dVar19 = *(f32 *)(piVar14 + 0x1a);
    piVar7 = (int *)Obj_GetActiveModel(obj);
    iVar5 = *piVar7;
    dVar19 = (longlong)(int)(lbl_803E74B4 * dVar19);
    for (iVar12 = 0; iVar12 < (int)(u32)*(u8 *)(iVar5 + 0xf8); iVar12 = iVar12 + 1) {
      iVar8 = ObjModel_GetRenderOp(iVar5,iVar12);
      *(char *)(iVar8 + 0x43) = (s8)(int)dVar19;
      local_88 = dVar19;
    }
    if ((piVar14[0x1f] == 5) && (*(char *)(piVar14 + 0x2b) == '\0')) {
      for (iVar12 = 0; (u8)iVar12 < 6; iVar12 = iVar12 + 1) {
        if ((u32)GameBit_Get((u8)iVar12 + 0x108) != 0) {
          *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
          goto LAB_8023d59c;
        }
      }
      *(u16 *)((int)piVar14 + 0xa6) = *(short *)((int)piVar14 + 0xa6) - (u16)framesThisStep;
      if (*(short *)((int)piVar14 + 0xa6) < 1) {
        iVar12 = randomGetRange(0,5);
        GameBit_Set(iVar12 + 0x108,1);
        *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
      }
    }
LAB_8023d59c:
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar19 = lbl_803E74EC;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, lbl_803E74F0 < dVar17)) {
      dVar19 = lbl_803E74F0;
    }
    dVar17 = lbl_803E74F4;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, lbl_803E74F8 < dVar16)) {
      dVar17 = lbl_803E74F8;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74E8 * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E74FC * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    if (lbl_803E74DC <= *(float *)(obj + 0x98)) {
      piVar14[0x22] = 0x13;
    }
    break;
  case 0x13:
    if (moveChanged) {
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,0x13,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C0E4[0];
      if (piVar14[0x1f] == 5) {
        *(f32 *)(piVar14 + 0x27) = lbl_803E74A8;
      }
      else {
        *(f32 *)(piVar14 + 0x27) = lbl_803E74F0;
      }
      *(s16 *)(piVar14 + 0x26) = 0xffff;
    }
    Sfx_KeepAliveLoopedObjectSound(obj,0x469);
    if ((piVar14[0x1f] == 5) && (*(char *)(piVar14 + 0x2b) == '\0')) {
      for (iVar12 = 0; (u8)iVar12 < 6; iVar12 = iVar12 + 1) {
        if ((u32)GameBit_Get((u8)iVar12 + 0x108) != 0) {
          *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
          goto LAB_8023d7cc;
        }
      }
      *(u16 *)((int)piVar14 + 0xa6) = *(short *)((int)piVar14 + 0xa6) - (u16)framesThisStep;
      if (*(short *)((int)piVar14 + 0xa6) < 1) {
        iVar12 = randomGetRange(0,5);
        GameBit_Set(iVar12 + 0x108,1);
        *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
      }
    }
LAB_8023d7cc:
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar19 = lbl_803E7520;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, lbl_803E74A8 < dVar17)) {
      dVar19 = lbl_803E74A8;
    }
    dVar17 = lbl_803E7524;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, lbl_803E7528 < dVar16)) {
      dVar17 = lbl_803E7528;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74E8 * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E74FC * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    *(u16 *)(piVar14 + 0x26) = *(short *)(piVar14 + 0x26) - (u16)framesThisStep;
    iVar12 = (int)*(f32 *)(piVar14 + 0x27);
    *(f32 *)(piVar14 + 0x27) = *(f32 *)(piVar14 + 0x27) - (f32)framesThisStep;
    if (piVar14[0x1f] == 5) {
      local_130[0] = 300;
      local_130[1] = 600;
    }
    else {
      local_130[0] = 0x122;
      local_130[1] = 0x28;
    }
    for (iVar8 = 0; (u8)iVar8 < 2; iVar8 = iVar8 + 1) {
      if ((((piVar14[5] == 0) && (*(short *)(piVar14 + 0x26) <= local_130[(u8)iVar8])) &&
          (local_130[(u8)iVar8] < (short)iVar12)) && (cVar11 = Obj_IsLoadingLocked(), cVar11 != '\0')) {
        iVar5 = Obj_AllocObjectSetup(0x24,0x819);
        *(int *)(iVar5 + 8) = piVar14[0x30];
        *(int *)(iVar5 + 0xc) = piVar14[0x31];
        *(int *)(iVar5 + 0x10) = piVar14[0x32];
        *(undefined *)(iVar5 + 4) = 1;
        *(undefined *)(iVar5 + 5) = 1;
        *(s16 *)(iVar5 + 0x20) = 0xffff;
        iVar5 = loadObjectAtObject(obj);
        piVar14[5] = iVar5;
        if (piVar14[5] != 0) {
          *(undefined *)(piVar14[5] + 0x36) = 0xff;
          *(undefined *)(piVar14[5] + 0x37) = 0xff;
          piVar14[0x25] = lbl_803DC4EC;
        }
      }
    }
    if (*(short *)(piVar14 + 0x26) < 0) {
      fn_8023A168(obj,(int)piVar14);
      *(short *)(piVar14 + 0x26) = (short)lbl_803DC46C;
    }
    if (*(f32 *)(piVar14 + 0x27) < lbl_803E74D4) {
      piVar14[0x22] = 0x14;
    }
    break;
  case 0x14:
    if (moveChanged) {
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,0x14,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C0E8[0];
    }
    if ((piVar14[0x1f] == 5) && (*(char *)(piVar14 + 0x2b) == '\0')) {
      for (iVar12 = 0; (u8)iVar12 < 6; iVar12 = iVar12 + 1) {
        if ((u32)GameBit_Get((u8)iVar12 + 0x108) != 0) {
          *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
          goto LAB_8023db24;
        }
      }
      *(u16 *)((int)piVar14 + 0xa6) = *(short *)((int)piVar14 + 0xa6) - (u16)framesThisStep;
      if (*(short *)((int)piVar14 + 0xa6) < 1) {
        iVar12 = randomGetRange(0,5);
        GameBit_Set(iVar12 + 0x108,1);
        *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
      }
    }
LAB_8023db24:
    lbl_803DDDCA = lbl_803DDDCA + lbl_803DC4BC;
    lbl_803DDDC8 = lbl_803DDDC8 + lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - *(f32 *)(piVar14 + 0x16));
    dVar16 = (*(float *)(*piVar14 + 0x10) - *(f32 *)(piVar14 + 0x17));
    dVar19 = lbl_803E74EC;
    if ((dVar19 <= dVar17) && (dVar19 = dVar17, lbl_803E74F0 < dVar17)) {
      dVar19 = lbl_803E74F0;
    }
    dVar17 = lbl_803E752C;
    if ((dVar17 <= dVar16) && (dVar17 = dVar16, lbl_803E74E8 < dVar16)) {
      dVar17 = lbl_803E74E8;
    }
        dVar16 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x33) = (lbl_803E74CC * dVar16 +
                     (float)(*(f32 *)(piVar14 + 0x16) + dVar19));
        dVar19 = fn_80293E80(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    *(f32 *)(piVar14 + 0x34) = (lbl_803E74FC * dVar19 +
                     (float)(*(f32 *)(piVar14 + 0x17) + dVar17));
    piVar14[0x35] = piVar14[0x18];
    if (lbl_803E74DC <= *(float *)(obj + 0x98)) {
      piVar14[0x21] = 1;
    }
    break;
  case 0x19:
  case 0x1a:
    if (moveChanged) {
      Sfx_PlayFromObject(obj,0x4a6);
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,4,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C0A8[0];
    }
    if (lbl_803E74DC <= *(float *)(obj + 0x98)) {
      piVar14[0x21] = 1;
    }
    break;
  case 0x1b:
    if (moveChanged) {
      GameBit_Set(0x10,0);
      *(s16 *)(piVar14 + 0x26) = 0x1e;
      fn_8022D308(*piVar14);
      *(int *)(*piVar14 + 0x14) = piVar14[0x1c];
      *(f32 *)(piVar14 + 0x2a) = lbl_803E74D4;
    }
    piVar14[0x33] = piVar14[0x16];
    piVar14[0x34] = piVar14[0x17];
    piVar14[0x35] = piVar14[0x18];
    iVar12 = GameBit_Get(0x10);
    if ((iVar12 != 0) &&
       (sVar3 = *(short *)(piVar14 + 0x26), *(short *)(piVar14 + 0x26) = sVar3 + -1, sVar3 == 0)) {
      GameBit_Set(0x10,0);
      piVar14[0x21] = 1;
    }
    break;
  case 0x1c:
    if (moveChanged) {
      androssbrain_setState(piVar14[3],1,0);
      ObjHits_DisableObject(obj);
      *(s16 *)(piVar14 + 0x26) = 0x3c;
      *(f32 *)(piVar14 + 0x27) = lbl_803E74D8;
      piVar14[0x33] = piVar14[0x16];
      piVar14[0x34] = piVar14[0x17];
      piVar14[0x35] = piVar14[0x18];
      fVar2 = lbl_803E74D4;
      *(float *)(obj + 0x24) = lbl_803E74D4;
      *(float *)(obj + 0x28) = fVar2;
      *(float *)(obj + 0x2c) = fVar2;
      *(f32 *)(piVar14 + 0x1d) = lbl_803E74C8;
      *(f32 *)(piVar14 + 0x1e) = lbl_803E7530;
    }
    *(f32 *)(piVar14 + 0x1a) = *(f32 *)(piVar14 + 0x1a) + lbl_803E751C;
    fVar2 = *(f32 *)(piVar14 + 0x1a);
    if (lbl_803E7534 < fVar2) {
      fVar2 = lbl_803E7534;
    }
    *(f32 *)(piVar14 + 0x1a) = fVar2;
    for (iVar12 = 0; (u8)iVar12 < 6; iVar12 = iVar12 + 1) {
      if ((u32)GameBit_Get((u8)iVar12 + 0x108) != 0) {
        *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
        goto LAB_8023de5c;
      }
    }
    *(u16 *)((int)piVar14 + 0xa6) = *(short *)((int)piVar14 + 0xa6) - (u16)framesThisStep;
    if (*(short *)((int)piVar14 + 0xa6) < 1) {
      iVar12 = randomGetRange(0,5);
      GameBit_Set(iVar12 + 0x108,1);
      *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
    }
LAB_8023de5c:
    *(u16 *)(piVar14 + 0x26) = *(short *)(piVar14 + 0x26) - (u16)framesThisStep;
    if (*(short *)(piVar14 + 0x26) < 0) {
      *(f32 *)(piVar14 + 0x27) = *(f32 *)(piVar14 + 0x27) - lbl_803E74DC;
      if (lbl_803E74D4 <= *(f32 *)(piVar14 + 0x27)) {
        uVar10 = randomGetRange(0x14,0x1e);
        *(s16 *)(piVar14 + 0x26) = uVar10;
        uVar6 = randomGetRange((int)-lbl_803DC470,(int)lbl_803DC470);
                *(f32 *)(piVar14 + 0x33) = *(f32 *)(piVar14 + 0x16) + (f32)(int)uVar6;
        uStack100 = randomGetRange((int)-lbl_803DC474,(int)lbl_803DC474);
        *(f32 *)(piVar14 + 0x34) = *(f32 *)(piVar14 + 0x17) + (f32)(int)uStack100;
        uVar6 = randomGetRange((int)-lbl_803DC478,(int)lbl_803DC478);
                *(f32 *)(piVar14 + 0x35) = *(f32 *)(piVar14 + 0x18) + (f32)(int)uVar6;
      }
      else {
        *(char *)(piVar14 + 0x2b) = *(char *)(piVar14 + 0x2b) + '\x01';
        if (*(u8 *)(piVar14 + 0x2b) < 4) {
          piVar14[0x22] = 0x1d;
        }
        else {
          piVar14[0x1f] = 5;
          piVar14[0x20] = 5;
          *(undefined *)(piVar14 + 0x2b) = 0;
          piVar14[0x22] = 0x12;
          androssbrain_setState(piVar14[3],0,0);
          ObjHits_EnableObject(obj);
        }
      }
    }
    if ((*(u8 *)((int)piVar14 + 0xad) & 8) != 0) {
      arwingHudSetVisible(2);
      GameBit_Set(1,1);
      GameBit_Set(0x4b1,1);
      piVar14[0x22] = 0x1e;
      unlockLevel(0,0,1);
      uVar9 = mapGetDirIdx(0xb);
      mapUnload(uVar9,0x20000000);
      Music_Trigger(0xf3,0);
    }
    dVar19 = *(f32 *)(piVar14 + 0x1a);
    piVar7 = (int *)Obj_GetActiveModel(obj);
    iVar5 = *piVar7;
    dVar19 = (longlong)(int)(lbl_803E74B4 * dVar19);
    for (iVar12 = 0; iVar12 < (int)(u32)*(u8 *)(iVar5 + 0xf8); iVar12 = iVar12 + 1) {
      iVar8 = ObjModel_GetRenderOp(iVar5,iVar12);
      *(char *)(iVar8 + 0x43) = (s8)(int)dVar19;
      local_50 = dVar19;
    }
    break;
  case 0x1d:
    if (moveChanged) {
      androssbrain_setState(piVar14[3],1,0);
      ObjHits_DisableObject(obj);
      *(short *)(piVar14 + 0x26) = (short)lbl_803DC484;
      piVar14[0x33] = *(int *)(*piVar14 + 0xc);
      *(f32 *)(piVar14 + 0x34) = *(float *)(*piVar14 + 0x10) + lbl_803DC47C;
      *(f32 *)(piVar14 + 0x35) = *(float *)(*piVar14 + 0x14) + lbl_803DC480;
      fVar2 = lbl_803E74D4;
      *(float *)(obj + 0x24) = lbl_803E74D4;
      *(float *)(obj + 0x28) = fVar2;
      *(float *)(obj + 0x2c) = fVar2;
      iVar12 = randomGetRange(0,1);
      if (iVar12 == 0) {
        uVar9 = 0x472;
      }
      else {
        uVar9 = 0x471;
      }
      Sfx_PlayFromObject(obj,uVar9);
    }
    *(u16 *)(piVar14 + 0x26) = *(short *)(piVar14 + 0x26) - (u16)framesThisStep;
    if (*(short *)(piVar14 + 0x26) < 0) {
      piVar14[0x22] = 0x1c;
    }
    break;
  case 0x16:
    if (moveChanged) {
      iVar12 = randomGetRange(0,1);
      if (iVar12 == 0) {
        uVar9 = 0x472;
      }
      else {
        uVar9 = 0x471;
      }
      Sfx_PlayFromObject(obj,uVar9);
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,0,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C098[0];
    }
    if (*(char *)(piVar14 + 0x2e) != '\0') {
      iVar12 = *piVar14;
      local_fc.x = (*(f32 *)(piVar14 + 0x30) - *(float *)(iVar12 + 0xc)) * lbl_803DC488;
      local_fc.y = (*(f32 *)(piVar14 + 0x31) - *(float *)(iVar12 + 0x10)) * lbl_803DC488;
      local_fc.z = (*(f32 *)(piVar14 + 0x32) - *(float *)(iVar12 + 0x14)) * lbl_803DC488;
      local_f0 = local_fc;
      fn_8022D4AC(iVar12,(int)&local_f0);
      fVar2 = -(lbl_803E753C * timeDelta - *(f32 *)(piVar14 + 0x2a));
      if (fVar2 < lbl_803E7538) {
        fVar2 = lbl_803E7538;
      }
      *(f32 *)(piVar14 + 0x2a) = fVar2;
    }
    sVar3 = *(short *)(piVar14 + 0x28) - *(s16 *)obj;
    if (0x8000 < sVar3) {
      sVar3 = sVar3 + 1;
    }
    if (sVar3 < -0x8000) {
      sVar3 = sVar3 + -1;
    }
    iVar12 = (int)sVar3;
    if (iVar12 < 0) {
      iVar12 = -iVar12;
    }
    if (iVar12 < 2000) {
      cVar11 = *(char *)(*(int *)(piVar14[1] + 0xb8) + 0x23);
      if ((((cVar11 != '\x02') && (cVar11 != '\x01')) &&
          (cVar11 = *(char *)(*(int *)(piVar14[2] + 0xb8) + 0x23), cVar11 != '\x02')) &&
         (cVar11 != '\x01')) {
        piVar14[0x21] = 1;
      }
    }
    break;
  case 5:
    iVar12 = *(int *)(piVar14[1] + 0xb8);
    iVar5 = *(int *)(piVar14[2] + 0xb8);
    if (moveChanged) {
      Sfx_PlayFromObject(obj,0x470);
      iVar8 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,0x16,lbl_803E74D4,0);
      *(f32 *)(iVar8 + 100) = lbl_8032C0F0[0];
      ((AndrossFlagByte *)((u8 *)piVar14 + 0xe8))->f80 = 0;
      ((AndrossFlagByte *)((u8 *)piVar14 + 0xe8))->f40 = 0;
    }
    dVar19 = *(float *)(obj + 0x98);
    if (lbl_803E7540 <= dVar19) {
      dVar19 = fn_80293E80(((lbl_803E74A0 *
                                             (float)(lbl_803E7548 *
                                                    (lbl_803E7558 *
                                                     ((dVar19 - lbl_803E7540) / lbl_803E7560)
                                                    + lbl_803E7550))) / lbl_803E74A4));
            *(f32 *)(piVar14 + 0x35) = ((f32)(lbl_803DC48C) * dVar19 +
                       *(f32 *)(piVar14 + 0x18));
    }
    else {
      dVar19 = fn_80293E80(((lbl_803E74A0 *
                                             (float)(lbl_803E7548 *
                                                    lbl_803E7550 * (dVar19 / lbl_803E7540))) /
                                            lbl_803E74A4));
      *(f32 *)(piVar14 + 0x35) = (lbl_803E74A8 * dVar19 + *(f32 *)(piVar14 + 0x18));
    }
    if ((lbl_803E7568 < *(float *)(obj + 0x98)) &&
       ((*(u8 *)(piVar14 + 0x3a) >> 6 & 1) == 0)) {
      iVar8 = randomGetRange(0,1);
      if (iVar8 == 0) {
        uVar9 = 0x472;
      }
      else {
        uVar9 = 0x471;
      }
      Sfx_PlayFromObject(obj,uVar9);
      ((AndrossFlagByte *)((u8 *)piVar14 + 0xe8))->f40 = 1;
    }
    if ((lbl_803E7570 < *(float *)(obj + 0x98)) && (-1 < *(char *)(piVar14 + 0x3a))) {
      Sfx_PlayFromObject(obj,0x46d);
      ((AndrossFlagByte *)((u8 *)piVar14 + 0xe8))->f80 = 1;
    }
    cVar11 = *(char *)(iVar12 + 0x23);
    if ((((cVar11 != '\x02') && (cVar11 != '\x01')) &&
        (cVar11 = *(char *)(iVar5 + 0x23), cVar11 != '\x02')) && (cVar11 != '\x01')) {
      if (*(float *)(obj + 0x98) < lbl_803E74DC) {
        if (lbl_803E7568 < *(float *)(obj + 0x98)) {
          *(s16 *)(piVar14 + 0x28) = 0;
            androsshand_setState(piVar14[1],1,(u8)((piVar14[0x1f] == 4) + 1));
          androsshand_setState(piVar14[2],1,(u8)((piVar14[0x1f] == 4) + 1));
          *(u8 *)((int)piVar14 + 0xad) = *(u8 *)((int)piVar14 + 0xad) & 0xf9;
        }
      }
      else {
        piVar14[0x21] = 1;
      }
    }
    break;
  case 0x17:
    if (moveChanged) {
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,3,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C0A4[0];
      *(f32 *)(piVar14 + 0x39) = lbl_803E74D4;
      ((AndrossFlagByte *)((u8 *)piVar14 + 0xe8))->f20 = 0;
    }
    *(f32 *)(piVar14 + 0x39) = *(f32 *)(piVar14 + 0x39) + timeDelta;
    if ((lbl_803E7578 < *(f32 *)(piVar14 + 0x39)) && ((*(u8 *)(piVar14 + 0x3a) >> 5 & 1) == 0)) {
      Sfx_PlayFromObject(obj,0x46f);
      ((AndrossFlagByte *)((u8 *)piVar14 + 0xe8))->f20 = 1;
    }
    if (*(float *)(obj + 0x98) <= lbl_803DC490) {
      piVar14[0x30] = *(int *)(obj + 0xc);
      *(f32 *)(piVar14 + 0x31) = *(float *)(obj + 0x10) - lbl_803E757C;
      *(f32 *)(piVar14 + 0x32) = *(float *)(obj + 0x14) - lbl_803E7580;
      iVar12 = *piVar14;
      local_114.x = (*(f32 *)(piVar14 + 0x30) - *(float *)(iVar12 + 0xc)) * lbl_803DC494;
      local_114.y = (*(f32 *)(piVar14 + 0x31) - *(float *)(iVar12 + 0x10)) * lbl_803DC494;
      local_114.z = (*(f32 *)(piVar14 + 0x32) - *(float *)(iVar12 + 0x14)) * lbl_803DC494;
      local_108 = local_114;
      fn_8022D4AC(iVar12,(int)&local_108);

    }
    else {
      dVar19 = (*(f32 *)(piVar14 + 0x1c) - *(float *)(*piVar14 + 0x14));
      fVar2 = lbl_803E753C * timeDelta + *(f32 *)(piVar14 + 0x2a);
      if (lbl_803E74D4 < fVar2) {
        fVar2 = lbl_803E74D4;
      }
      *(f32 *)(piVar14 + 0x2a) = fVar2;
      *(undefined *)(piVar14 + 0x2e) = 0;
      *(u16 *)(*piVar14 + 6) = *(u16 *)(*piVar14 + 6) & 0xbfff;
      sVar3 = fn_8022D46C(*piVar14);
            iVar12 = (int)(dVar19 * lbl_803DC49C + (f32)(sVar3));
      fn_8022D47C(*piVar14,iVar12);
      local_9c.x = lbl_803E74D4;
      local_9c.y = lbl_803E74D4;
      local_9c.z = (float)(dVar19 * lbl_803DC498);
      local_b4 = local_9c;
      fn_8022D4AC(*piVar14,(int)&local_b4);
    }
    if (lbl_803E74DC <= *(float *)(obj + 0x98)) {
      piVar14[0x21] = 1;
    }
    break;
  case 0x18:
    if (moveChanged) {
      iVar12 = *(int *)(obj + 0xb8);
      ObjAnim_SetCurrentMove(obj,0x11,lbl_803E74D4,0);
      *(f32 *)(iVar12 + 100) = lbl_8032C0DC[0];
      ((AndrossFlagByte *)((u8 *)piVar14 + 0xe8))->f20 = 0;
    }
    if (*(float *)(obj + 0x98) <= lbl_803DC4A0) {
      iVar12 = *piVar14;
      local_12c.x = (*(f32 *)(piVar14 + 0x30) - *(float *)(iVar12 + 0xc)) * lbl_803DC4A4;
      local_12c.y = (*(f32 *)(piVar14 + 0x31) - *(float *)(iVar12 + 0x10)) * lbl_803DC4A4;
      local_12c.z = (*(f32 *)(piVar14 + 0x32) - *(float *)(iVar12 + 0x14)) * lbl_803DC4A4;
      local_120 = local_12c;
      fn_8022D4AC(iVar12,(int)&local_120);

    }
    else {
      dVar19 = (*(f32 *)(piVar14 + 0x1c) - *(float *)(*piVar14 + 0x14));
      fVar2 = lbl_803E7514 * timeDelta + *(f32 *)(piVar14 + 0x2a);
      if (lbl_803E74D4 < fVar2) {
        fVar2 = lbl_803E74D4;
      }
      *(f32 *)(piVar14 + 0x2a) = fVar2;
      *(undefined *)(piVar14 + 0x2e) = 0;
      *(u16 *)(*piVar14 + 6) = *(u16 *)(*piVar14 + 6) & 0xbfff;
      sVar3 = fn_8022D46C(*piVar14);
            iVar12 = (int)(dVar19 * lbl_803DC4AC + (f32)(sVar3));
      fn_8022D47C(*piVar14,iVar12);
      local_a8.x = lbl_803E74D4;
      local_a8.y = lbl_803E74D4;
      local_a8.z = (float)(dVar19 * lbl_803DC4A8);
      local_c0 = local_a8;
      fn_8022D4AC(*piVar14,(int)&local_c0);
      if ((*(u8 *)(piVar14 + 0x3a) >> 5 & 1) == 0) {
        Sfx_PlayFromObject(obj,0x46f);
        ((AndrossFlagByte *)((u8 *)piVar14 + 0xe8))->f20 = 1;
      }
    }
    if (lbl_803E74DC <= *(float *)(obj + 0x98)) {
      piVar14[0x21] = 1;
    }
    break;
  case 0x1e:
    iVar12 = GameBit_Get(2);
    if (((iVar12 != 0) || (iVar12 = GameBit_Get(3), iVar12 != 0)) ||
       (iVar12 = GameBit_Get(4), iVar12 != 0)) {
      GameBit_Set(0x405,0);
      (*(void (*)())*(int *)(*gMapEventInterface + 0x44))(0xb,7);
      unlockLevel(0,0,1);
      loadMapAndParent(mapGetDirIdx(0xb));
      uVar9 = mapGetDirIdx(0xb);
      lockLevel(uVar9,1);
      warpToMap(0x4e,0);
      *(f32 *)(piVar14 + 0x1a) = lbl_803E74D4;
      piVar14[0x22] = 0x1f;
    }
  }
  local_134 = lbl_803E7584 + *(f32 *)(piVar14 + 0x2a);
  (*(void (*)())*(int *)(*gCameraInterface + 0x60))(&local_134,4);
  *(float *)(obj + 0x24) =
       *(f32 *)(piVar14 + 0x1d) * (*(f32 *)(piVar14 + 0x33) - *(float *)(obj + 0xc)) +
       *(float *)(obj + 0x24);
  *(float *)(obj + 0x28) =
       *(f32 *)(piVar14 + 0x1d) * (*(f32 *)(piVar14 + 0x34) - *(float *)(obj + 0x10)) +
       *(float *)(obj + 0x28);
  *(float *)(obj + 0x2c) =
       *(f32 *)(piVar14 + 0x1d) * (*(f32 *)(piVar14 + 0x35) - *(float *)(obj + 0x14)) +
       *(float *)(obj + 0x2c);
  *(float *)(obj + 0x24) = *(float *)(obj + 0x24) * *(f32 *)(piVar14 + 0x1e);
  *(float *)(obj + 0x28) = *(float *)(obj + 0x28) * *(f32 *)(piVar14 + 0x1e);
  *(float *)(obj + 0x2c) = *(float *)(obj + 0x2c) * *(f32 *)(piVar14 + 0x1e);
  *(float *)(obj + 0xc) = *(float *)(obj + 0xc) + *(float *)(obj + 0x24);
  *(float *)(obj + 0x10) = *(float *)(obj + 0x10) + *(float *)(obj + 0x28);
  *(float *)(obj + 0x14) = *(float *)(obj + 0x14) + *(float *)(obj + 0x2c);
  if (lbl_803E74D4 == *(f32 *)(piVar14 + 0x38)) {
    if (*(char *)(piVar14 + 0x2e) == '\0') {
      *(f32 *)(piVar14 + 0x38) = lbl_803DC4B0 * (*(f32 *)(piVar14 + 0x1c) - *(float *)(*piVar14 + 0x14));
    }
    else {
      fn_8023A6A4((int)piVar14,lbl_803DC4B4,lbl_803DC4B8,lbl_803E74D4);
    }
  }
  if (*(int *)(*piVar14 + 0xc0) == 0) {
    local_cc = *(SunVec3 *)(piVar14 + 0x36);
    fn_8022D4CC(*piVar14,(int)&local_cc);
  }
  sVar3 = *(short *)(piVar14 + 0x28) - *(s16 *)obj;
  if (0x8000 < sVar3) {
    sVar3 = sVar3 + 1;
  }
  if (sVar3 < -0x8000) {
    sVar3 = sVar3 + -1;
  }
  *(short *)((int)piVar14 + 0xa2) =
       *(short *)((int)piVar14 + 0xa2) +
       (short)(((int)sVar3 / lbl_803DC430 - (int)*(short *)((int)piVar14 + 0xa2)) / lbl_803DC434);
  *(short *)(piVar14 + 0x29) =
       *(short *)(piVar14 + 0x29) +
       (short)((-(int)*(s16 *)(obj + 2) / lbl_803DC430 - (int)*(short *)(piVar14 + 0x29)) / lbl_803DC434);
  *(s16 *)obj = *(s16 *)obj + *(short *)((int)piVar14 + 0xa2);
  *(s16 *)(obj + 2) = *(s16 *)(obj + 2) + *(short *)(piVar14 + 0x29);
  ObjAnim_AdvanceCurrentMove(*(f32 *)(piVar14 + 0x19),timeDelta,obj,0);
  fn_8023A3E4(obj,(int)piVar14);
  fn_8023A87C(obj,(int)piVar14);
  iVar12 = piVar14[5];
  if (iVar12 != 0) {
    *(float *)(iVar12 + 0x14) = *(float *)(iVar12 + 0x14) - lbl_803E74D8;
    piVar14[0x25] = piVar14[0x25] - (u32)framesThisStep;
    if (piVar14[0x25] < 0) {
      Obj_FreeObject(piVar14[5]);
      piVar14[0x25] = 0;
      piVar14[5] = 0;
    }
  }
  if (piVar14[0x1f] < 6) {
    local_138 = lbl_803E7490;
    iVar12 = ObjList_FindNearestObjectByDefNo(obj,0x7e5,&local_138);
    if (iVar12 != 0) {
      if (*(int *)(iVar12 + 0xc0) != 0) {
        iVar12 = *(int *)(iVar12 + 0xc0);
      }
      if ((*(short *)(iVar12 + 0x44) != 0x10) ||
         (iVar5 = animatedObjGetSeqId(*(int *)(iVar12 + 0xb8)), iVar5 != 0x598)) {
        *(int *)(*(int *)(iVar12 + 0x4c) + 8) = *(int *)(obj + 0xc);
        *(int *)(*(int *)(iVar12 + 0x4c) + 0xc) = *(int *)(obj + 0x10);
        *(int *)(*(int *)(iVar12 + 0x4c) + 0x10) = *(int *)(obj + 0x14);
      }
    }
    local_13c = lbl_803E7490;
    iVar12 = ObjList_FindNearestObjectByDefNo(obj,0x1e,&local_13c);
    if (iVar12 != 0) {
      if (*(int *)(iVar12 + 0xc0) != 0) {
        iVar12 = *(int *)(iVar12 + 0xc0);
      }
      if ((*(short *)(iVar12 + 0x44) != 0x10) ||
         (iVar5 = animatedObjGetSeqId(*(int *)(iVar12 + 0xb8)), iVar5 != 0x598)) {
        *(int *)(*(int *)(iVar12 + 0x4c) + 8) = *(int *)(obj + 0xc);
        *(int *)(*(int *)(iVar12 + 0x4c) + 0xc) = *(int *)(obj + 0x10);
        *(int *)(*(int *)(iVar12 + 0x4c) + 0x10) = *(int *)(obj + 0x14);
      }
    }
    local_140 = lbl_803E7490;
    iVar12 = ObjList_FindNearestObjectByDefNo(obj,0x76f,&local_140);
    if (iVar12 != 0) {
      if (*(int *)(iVar12 + 0xc0) != 0) {
        iVar12 = *(int *)(iVar12 + 0xc0);
      }
      if ((*(short *)(iVar12 + 0x44) != 0x10) ||
         (iVar5 = animatedObjGetSeqId(*(int *)(iVar12 + 0xb8)), iVar5 != 0x598)) {
        *(int *)(*(int *)(iVar12 + 0x4c) + 8) = *(int *)(obj + 0xc);
        *(int *)(*(int *)(iVar12 + 0x4c) + 0xc) = *(int *)(obj + 0x10);
        *(int *)(*(int *)(iVar12 + 0x4c) + 0x10) = *(int *)(obj + 0x14);
      }
    }
    local_144 = lbl_803E7490;
    iVar12 = ObjList_FindNearestObjectByDefNo(obj,0x814,&local_144);
    if (iVar12 != 0) {
      if (*(int *)(iVar12 + 0xc0) != 0) {
        iVar12 = *(int *)(iVar12 + 0xc0);
      }
      if ((*(short *)(iVar12 + 0x44) != 0x10) ||
         (iVar5 = animatedObjGetSeqId(*(int *)(iVar12 + 0xb8)), iVar5 != 0x598)) {
        *(int *)(*(int *)(iVar12 + 0x4c) + 8) = *(int *)(obj + 0xc);
        *(int *)(*(int *)(iVar12 + 0x4c) + 0xc) = *(int *)(obj + 0x10);
        *(int *)(*(int *)(iVar12 + 0x4c) + 0x10) = *(int *)(obj + 0x14);
      }
    }
    local_148 = lbl_803E7490;
    iVar12 = ObjList_FindNearestObjectByDefNo(obj,0x6cf,&local_148);
    if (iVar12 != 0) {
      if (*(int *)(iVar12 + 0xc0) != 0) {
        iVar12 = *(int *)(iVar12 + 0xc0);
      }
      if ((*(short *)(iVar12 + 0x44) != 0x10) ||
         (iVar5 = animatedObjGetSeqId(*(int *)(iVar12 + 0xb8)), iVar5 != 0x598)) {
        *(int *)(*(int *)(iVar12 + 0x4c) + 8) = *(int *)(obj + 0xc);
        *(int *)(*(int *)(iVar12 + 0x4c) + 0xc) = *(int *)(obj + 0x10);
        *(int *)(*(int *)(iVar12 + 0x4c) + 0x10) = *(int *)(obj + 0x14);
      }
    }
  }
LAB_8023ef14:
  return;
}


#pragma scheduling reset
#pragma peephole reset
