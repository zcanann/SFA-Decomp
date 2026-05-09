#include "ghidra_import.h"
#include "main/dll/CAM/camTalk.h"

extern void *memset(void *dst, int val, u32 n);
extern void *mmAlloc(int size, int heap, int flags);
extern undefined4 Obj_TransformWorldPointToLocal();
extern undefined4 FUN_80006a1c();
extern undefined4 FUN_80006a30();
extern int FUN_80017730();
extern void fn_80021AC8(void *param_1, void *outVec);
extern undefined4 fn_80021EE8();
extern undefined4 Matrix_TransformPoint();
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017830();
extern undefined4 camcontrol_getTargetPosition(int param_1,int param_2,float *outPos,void *outAngle);
extern void curvesMove(void *param_1);
extern double curveFn_80010dc0(double param_1,float *param_2,float *param_3);
extern void curveFn_80010d54(void);
extern int getAngle(double dx,double dz);
extern void *fn_801E1DA8(void);
extern int fn_801E12DC(int *obj);
extern double FUN_80293900();
extern double fn_80293E80(double);
extern f32 sqrtf(f32 value);
extern double sin(double);
extern void fn_80296BD4(int obj, float *x, float *y, float *z);

extern int *lbl_803DCA50;
extern u8* lbl_803DD540;
extern u8* lbl_803DD548;
extern f64 lbl_803E17B8;
extern f64 DOUBLE_803e2458;
extern f32 timeDelta;
extern f32 lbl_803E1780;
extern f32 lbl_803E1784;
extern f32 lbl_803E1788;
extern f32 lbl_803E178C;
extern f32 lbl_803E1790;
extern f32 lbl_803E1794;
extern f32 lbl_803E1798;
extern f32 lbl_803E179C;
extern f32 lbl_803E17A0;
extern f32 lbl_803E17A4;
extern f32 lbl_803E17A8;
extern f32 lbl_803E17AC;
extern f32 lbl_803E17B0;
extern f32 lbl_803E17B4;
extern f32 lbl_803E17C0;
extern f32 lbl_803E17C4;
extern f32 lbl_803E17C8;
extern f32 lbl_803E17CC;
extern f32 lbl_803E17D0;
extern f64 lbl_803E17D8;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f32 lbl_803E2448;
extern f32 lbl_803E244C;
extern f32 lbl_803E2450;

typedef struct CamTalkTransformInput {
  ushort yaw;
  undefined2 pitch;
  undefined2 roll;
  undefined2 pad;
  float scale;
  float x;
  float y;
  float z;
} CamTalkTransformInput;

/*
 * --INFO--
 *
 * Function: FUN_80107b4c
 * EN v1.0 Address: 0x80107B4C
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80107DBC
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80107b4c(void)
{
  FUN_80017814(lbl_803DD540);
  lbl_803DD540 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80107B4C
 * EN v1.0 Address: 0x80107B78
 * EN v1.0 Size: 872b
 * EN v1.1 Address: 0x80107DE8
 * EN v1.1 Size: 1076b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80107B4C(short *param_1)
{
  int iVar1;
  float fVar2;
  float fVar3;
  short sVar4;
  ushort *puVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  float local_108;
  float local_104;
  float local_100;
  CamTalkTransformInput local_fc;
  float afStack_e4 [17];
  longlong local_a0;
  undefined4 local_98;
  uint uStack_94;
  longlong local_90;
  longlong local_88;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
  longlong local_60;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  longlong local_48;
  
  (*(code *)(*lbl_803DCA50 + 0x18))();
  puVar5 = *(ushort **)(param_1 + 0x52);
  if (puVar5 != (ushort *)0x0) {
    *(float *)(param_1 + 0x5a) = lbl_803E1784;
    local_fc.x = *(float *)(puVar5 + 0xc);
    local_fc.y = *(float *)(puVar5 + 0xe);
    local_fc.z = *(float *)(puVar5 + 0x10);
    local_fc.scale = lbl_803E1788;
    local_fc.yaw = *puVar5;
    local_a0 = (longlong)(int)*(float *)(lbl_803DD540 + 0x30);
    local_fc.pitch = (undefined2)(int)*(float *)(lbl_803DD540 + 0x30);
    local_fc.roll = 0;
    fn_80021EE8(afStack_e4,&local_fc);
    Matrix_TransformPoint((double)lbl_803E1780,(double)lbl_803E178C,(double)lbl_803E1780,afStack_e4,
                 &local_100,&local_104,&local_108);
    *param_1 = -0x8000 - *puVar5;
    *(float *)(lbl_803DD540 + 0x20) =
         lbl_803E1790 *
         (lbl_803E1794 * *(float *)(lbl_803DD540 + 0x1c) - *(float *)(lbl_803DD540 + 0x20)) +
         *(float *)(lbl_803DD540 + 0x20);
    uStack_94 = (int)*param_1 ^ 0x80000000;
    local_98 = 0x43300000;
    iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_94) - lbl_803E17B8) +
                 *(float *)(lbl_803DD540 + 0x20));
    local_90 = (longlong)iVar1;
    *param_1 = (short)iVar1;
    iVar1 = (int)(lbl_803E1798 - *(float *)(lbl_803DD540 + 0x30));
    local_88 = (longlong)iVar1;
    sVar4 = (short)iVar1 - param_1[1];
    if (0x8000 < sVar4) {
      sVar4 = sVar4 + 1;
    }
    if (sVar4 < -0x8000) {
      sVar4 = sVar4 + -1;
    }
    param_1[1] = param_1[1] + (sVar4 >> 3);
    uStack_7c = (int)*param_1 - 0x4000U ^ 0x80000000;
    local_80 = 0x43300000;
    dVar6 = (double)fn_80293E80((double)(lbl_803E179C *
        (float)((double)CONCAT44(0x43300000,uStack_7c) - lbl_803E17B8) / lbl_803E17A0));
    uStack_74 = (int)*param_1 - 0x4000U ^ 0x80000000;
    local_78 = 0x43300000;
    dVar7 = (double)sin((double)(lbl_803E179C *
        (float)((double)CONCAT44(0x43300000,uStack_74) - lbl_803E17B8) / lbl_803E17A0));
    uStack_6c = (int)param_1[1] ^ 0x80000000;
    local_70 = 0x43300000;
    dVar8 = (double)sin((double)(lbl_803E179C *
        (float)((double)CONCAT44(0x43300000,uStack_6c) - lbl_803E17B8) / lbl_803E17A0));
    uStack_64 = (int)param_1[1] ^ 0x80000000;
    local_68 = 0x43300000;
    dVar9 = (double)fn_80293E80((double)(lbl_803E179C *
        (float)((double)CONCAT44(0x43300000,uStack_64) - lbl_803E17B8) / lbl_803E17A0));
    fVar2 = -*(float *)(lbl_803DD540 + 0x24) / lbl_803E17A4;
    fVar3 = lbl_803E1780;
    if ((lbl_803E1780 <= fVar2) && (fVar3 = fVar2, lbl_803E1788 < fVar2)) {
      fVar3 = lbl_803E1788;
    }
    *(float *)(lbl_803DD540 + 0x28) =
         lbl_803E17A8 *
         ((lbl_803E17B0 * fVar3 + lbl_803E17AC) - *(float *)(lbl_803DD540 + 0x28)) +
         *(float *)(lbl_803DD540 + 0x28);
    fVar2 = *(float *)(lbl_803DD540 + 0x28);
    dVar8 = (double)(float)((double)fVar2 * dVar8);
    *(float *)(param_1 + 0xc) = local_100 + (float)(dVar8 * dVar7);
    *(float *)(param_1 + 0xe) = local_104 + (float)((double)fVar2 * dVar9);
    *(float *)(param_1 + 0x10) = local_108 + (float)(dVar8 * dVar6);
    iVar1 = (int)(lbl_803E17A8 * *(float *)(lbl_803DD540 + 0x2c));
    local_60 = (longlong)iVar1;
    sVar4 = (short)iVar1 - param_1[2];
    if (0x8000 < sVar4) {
      sVar4 = sVar4 + 1;
    }
    if (sVar4 < -0x8000) {
      sVar4 = sVar4 + -1;
    }
    uStack_54 = (int)sVar4 ^ 0x80000000;
    local_58 = 0x43300000;
    uStack_4c = (int)param_1[2] ^ 0x80000000;
    local_50 = 0x43300000;
    iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_54) - lbl_803E17B8) * timeDelta
                  * lbl_803E17B4 +
                 (float)((double)CONCAT44(0x43300000,uStack_4c) - lbl_803E17B8));
    local_48 = (longlong)iVar1;
    param_1[2] = (short)iVar1;
    Obj_TransformWorldPointToLocal((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80107F80
 * EN v1.0 Address: 0x80107EE0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010821C
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80107F80(int param_1)
{
  if (lbl_803DD540 == 0) {
    lbl_803DD540 = (u8 *)mmAlloc(0x38,0xf,0);
  }
  memset(lbl_803DD540,0,0x38);
  *(float *)(lbl_803DD540 + 0x18) = *(float *)(param_1 + 0xb4);
  *(float *)(lbl_803DD540 + 0) = lbl_803E1784;
  *(float *)(lbl_803DD540 + 0x14) = lbl_803E1788;
  *(float *)(lbl_803DD540 + 0x28) = lbl_803E17AC;
}

/*
 * --INFO--
 *
 * Function: fn_80108010
 * EN v1.0 Address: 0x80107EE4
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x801082AC
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80108010(int param_1,int param_2)
{
  int *puVar1;
  int iVar2;
  float local_20;
  float local_24;
  float local_28;
  float local_1c[3];
  
  if (*(short *)(param_1 + 0x44) == 1) {
    fn_80296BD4(param_1,&local_28,&local_24,&local_20);
    if (((param_2 != 0) || (*(float *)(lbl_803DD548 + 0x120) != local_28)) ||
       (*(float *)(lbl_803DD548 + 0x128) != local_20)) {
      *(float *)(lbl_803DD548 + 0x130) = local_24;
    }
    *(float *)(lbl_803DD548 + 0x120) = local_28;
    *(float *)(lbl_803DD548 + 0x124) = local_24;
    *(float *)(lbl_803DD548 + 0x128) = local_20;
  }
  else {
    *(float *)(lbl_803DD548 + 0x120) = *(float *)(param_1 + 0x18);
    *(float *)(lbl_803DD548 + 0x124) = lbl_803E17C0 + *(float *)(param_1 + 0x1c);
    *(float *)(lbl_803DD548 + 0x128) = *(float *)(param_1 + 0x20);
    *(float *)(lbl_803DD548 + 0x130) = *(float *)(lbl_803DD548 + 0x124);
  }
  puVar1 = (int *)fn_801E1DA8();
  if ((puVar1 != (int *)0x0) && (iVar2 = fn_801E12DC(puVar1), iVar2 == 2)) {
    local_1c[0] = *(float *)(param_1 + 0x18) - *(float *)(puVar1 + 6);
    local_1c[1] = (lbl_803E17C0 + *(float *)(param_1 + 0x1c)) - *(float *)(puVar1 + 7);
    local_1c[2] = *(float *)(param_1 + 0x20) - *(float *)(puVar1 + 8);
    fn_80021AC8(puVar1,local_1c);
    *(float *)(lbl_803DD548 + 0x120) = *(float *)(puVar1 + 6) + local_1c[0];
    *(float *)(lbl_803DD548 + 0x124) = *(float *)(puVar1 + 7) + local_1c[1];
    *(float *)(lbl_803DD548 + 0x128) = *(float *)(puVar1 + 8) + local_1c[2];
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80108194
 * EN v1.0 Address: 0x80108074
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80108430
 * EN v1.1 Size: 744b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80108194(short *param_1)
{
  float fVar1;
  float fVar2;
  short sVar3;
  int iVar4;
  double dVar5;
  float local_24[3];
  undefined auStack_28[4];
  undefined4 local_18;
  uint uStack_14;
  undefined4 local_10;
  uint uStack_c;

  iVar4 = *(int *)(param_1 + 0x52);
  *(float *)(lbl_803DD548 + 0x10) = *(float *)(param_1 + 0xc);
  fVar1 = lbl_803E17C4;
  *(float *)(lbl_803DD548 + 0x18) = lbl_803E17C4;
  *(float *)(lbl_803DD548 + 0x1c) = fVar1;
  *(float *)(lbl_803DD548 + 0x20) = *(float *)(param_1 + 0xe);
  *(float *)(lbl_803DD548 + 0x28) = fVar1;
  *(float *)(lbl_803DD548 + 0x2c) = fVar1;
  *(float *)(lbl_803DD548 + 0x30) = *(float *)(param_1 + 0x10);
  *(float *)(lbl_803DD548 + 0x38) = fVar1;
  *(float *)(lbl_803DD548 + 0x3c) = fVar1;
  camcontrol_getTargetPosition((int)param_1,iVar4,local_24,auStack_28);
  *(float *)(lbl_803DD548 + 0x14) = local_24[0];
  *(float *)(lbl_803DD548 + 0x24) = local_24[1];
  *(float *)(lbl_803DD548 + 0x34) = local_24[2];
  fVar1 = *(float *)(lbl_803DD548 + 0x14) - *(float *)(lbl_803DD548 + 0x10);
  fVar2 = *(float *)(lbl_803DD548 + 0x34) - *(float *)(lbl_803DD548 + 0x30);
  dVar5 = (double)sqrtf(fVar1 * fVar1 + fVar2 * fVar2);
  *(float *)(lbl_803DD548 + 0x118) = (float)dVar5;
  *(int *)(lbl_803DD548 + 0xfc) = (int)(lbl_803DD548 + 0x40);
  *(int *)(lbl_803DD548 + 0x100) = (int)(lbl_803DD548 + 0x50);
  *(undefined4 *)(lbl_803DD548 + 0x104) = 0;
  *(undefined4 *)(lbl_803DD548 + 0x108) = 4;
  *(undefined4 *)(lbl_803DD548 + 0xf8) = 0;
  *(code **)(lbl_803DD548 + 0x10c) = (code *)curveFn_80010dc0;
  *(void **)(lbl_803DD548 + 0x110) = curveFn_80010d54;
  uStack_14 = (int)*param_1 ^ 0x80000000;
  local_18 = 0x43300000;
  *(float *)(lbl_803DD548 + 0x40) =
      (float)((double)CONCAT44(0x43300000,uStack_14) - lbl_803E17D8);
  sVar3 = getAngle((double)(*(float *)(lbl_803DD548 + 0x14) - *(float *)(iVar4 + 0x18)),
                   (double)(*(float *)(lbl_803DD548 + 0x34) - *(float *)(iVar4 + 0x20)));
  *(float *)(lbl_803DD548 + 0x44) =
      (float)((double)CONCAT44(0x43300000,(int)(short)(-0x8000 - sVar3) ^ 0x80000000) -
              lbl_803E17D8);
  fVar1 = lbl_803E17C4;
  *(float *)(lbl_803DD548 + 0x48) = lbl_803E17C4;
  *(float *)(lbl_803DD548 + 0x4c) = fVar1;
  fVar1 = *(float *)(lbl_803DD548 + 0x40) - *(float *)(lbl_803DD548 + 0x44);
  if ((lbl_803E17C8 < fVar1) || (fVar1 < lbl_803E17CC)) {
    if (lbl_803E17C4 <= *(float *)(lbl_803DD548 + 0x40)) {
      if (*(float *)(lbl_803DD548 + 0x44) < lbl_803E17C4) {
        *(float *)(lbl_803DD548 + 0x44) = *(float *)(lbl_803DD548 + 0x44) + lbl_803E17D0;
      }
    }
    else {
      *(float *)(lbl_803DD548 + 0x40) = *(float *)(lbl_803DD548 + 0x40) + lbl_803E17D0;
    }
  }
  uStack_c = (int)param_1[1] ^ 0x80000000;
  local_10 = 0x43300000;
  *(float *)(lbl_803DD548 + 0x50) =
      (float)((double)CONCAT44(0x43300000,uStack_c) - lbl_803E17D8);
  fVar1 = lbl_803E17C4;
  *(float *)(lbl_803DD548 + 0x54) = lbl_803E17C4;
  *(float *)(lbl_803DD548 + 0x58) = fVar1;
  *(float *)(lbl_803DD548 + 0x5c) = fVar1;
  fVar1 = *(float *)(lbl_803DD548 + 0x50) - *(float *)(lbl_803DD548 + 0x54);
  if ((lbl_803E17C8 < fVar1) || (fVar1 < lbl_803E17CC)) {
    if (lbl_803E17C4 <= *(float *)(lbl_803DD548 + 0x50)) {
      if (*(float *)(lbl_803DD548 + 0x54) < lbl_803E17C4) {
        *(float *)(lbl_803DD548 + 0x54) = *(float *)(lbl_803DD548 + 0x54) + lbl_803E17D0;
      }
    }
    else {
      *(float *)(lbl_803DD548 + 0x50) = *(float *)(lbl_803DD548 + 0x50) + lbl_803E17D0;
    }
  }
  curvesMove(lbl_803DD548 + 0x78);
}


/* Trivial 4b 0-arg blr leaves. */
void CameraModeBike_release(void) {}
void CameraModeBike_initialise(void) {}
