#include "ghidra_import.h"
#include "main/dll/DB/DBbonedust.h"
#include "main/dll/CAM/camTalk.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_800068f4();
extern undefined4 FUN_80006a1c();
extern undefined4 FUN_80006a30();
extern int FUN_80017730();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017754();
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017830();
extern undefined4 camcontrol_getTargetPosition();
extern undefined4 FUN_801e1ee4();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_80294d78();

extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803de1b8;
extern undefined4 DAT_803de1c0;
extern f64 DOUBLE_803e2438;
extern f64 DOUBLE_803e2458;
extern f32 lbl_803DC074;
extern f32 lbl_803E2400;
extern f32 lbl_803E2404;
extern f32 lbl_803E2408;
extern f32 lbl_803E240C;
extern f32 lbl_803E2410;
extern f32 lbl_803E2414;
extern f32 lbl_803E2418;
extern f32 lbl_803E2424;
extern f32 lbl_803E2428;
extern f32 lbl_803E242C;
extern f32 lbl_803E2430;
extern f32 lbl_803E2434;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f32 lbl_803E2448;
extern f32 lbl_803E244C;
extern f32 lbl_803E2450;

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
  FUN_80017814(DAT_803de1b8);
  DAT_803de1b8 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80107b78
 * EN v1.0 Address: 0x80107B78
 * EN v1.0 Size: 872b
 * EN v1.1 Address: 0x80107DE8
 * EN v1.1 Size: 1076b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80107b78(short *param_1)
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
  ushort local_fc;
  undefined2 local_fa;
  undefined2 local_f8;
  float local_f4;
  undefined4 local_f0;
  undefined4 local_ec;
  undefined4 local_e8;
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
  
  (**(code **)(*DAT_803dd6d0 + 0x18))();
  puVar5 = *(ushort **)(param_1 + 0x52);
  if (puVar5 != (ushort *)0x0) {
    *(float *)(param_1 + 0x5a) = lbl_803E2404;
    local_f0 = *(undefined4 *)(puVar5 + 0xc);
    local_ec = *(undefined4 *)(puVar5 + 0xe);
    local_e8 = *(undefined4 *)(puVar5 + 0x10);
    local_f4 = lbl_803E2408;
    local_fc = *puVar5;
    local_a0 = (longlong)(int)*(float *)(DAT_803de1b8 + 0x30);
    local_fa = (undefined2)(int)*(float *)(DAT_803de1b8 + 0x30);
    local_f8 = 0;
    FUN_80017754(afStack_e4,&local_fc);
    FUN_80017778((double)lbl_803E2400,(double)lbl_803E240C,(double)lbl_803E2400,afStack_e4,
                 &local_100,&local_104,&local_108);
    *param_1 = -0x8000 - *puVar5;
    *(float *)(DAT_803de1b8 + 0x20) =
         lbl_803E2410 *
         (lbl_803E2414 * *(float *)(DAT_803de1b8 + 0x1c) - *(float *)(DAT_803de1b8 + 0x20)) +
         *(float *)(DAT_803de1b8 + 0x20);
    uStack_94 = (int)*param_1 ^ 0x80000000;
    local_98 = 0x43300000;
    iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e2438) +
                 *(float *)(DAT_803de1b8 + 0x20));
    local_90 = (longlong)iVar1;
    *param_1 = (short)iVar1;
    iVar1 = (int)(lbl_803E2418 - *(float *)(DAT_803de1b8 + 0x30));
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
    dVar6 = (double)FUN_80293f90();
    uStack_74 = (int)*param_1 - 0x4000U ^ 0x80000000;
    local_78 = 0x43300000;
    dVar7 = (double)FUN_80294964();
    uStack_6c = (int)param_1[1] ^ 0x80000000;
    local_70 = 0x43300000;
    dVar8 = (double)FUN_80294964();
    uStack_64 = (int)param_1[1] ^ 0x80000000;
    local_68 = 0x43300000;
    dVar9 = (double)FUN_80293f90();
    fVar2 = -*(float *)(DAT_803de1b8 + 0x24) / lbl_803E2424;
    fVar3 = lbl_803E2400;
    if ((lbl_803E2400 <= fVar2) && (fVar3 = fVar2, lbl_803E2408 < fVar2)) {
      fVar3 = lbl_803E2408;
    }
    *(float *)(DAT_803de1b8 + 0x28) =
         lbl_803E2428 *
         ((lbl_803E2430 * fVar3 + lbl_803E242C) - *(float *)(DAT_803de1b8 + 0x28)) +
         *(float *)(DAT_803de1b8 + 0x28);
    fVar2 = *(float *)(DAT_803de1b8 + 0x28);
    dVar8 = (double)(float)((double)fVar2 * dVar8);
    *(float *)(param_1 + 0xc) = local_100 + (float)(dVar8 * dVar7);
    *(float *)(param_1 + 0xe) = local_104 + (float)((double)fVar2 * dVar9);
    *(float *)(param_1 + 0x10) = local_108 + (float)(dVar8 * dVar6);
    iVar1 = (int)(lbl_803E2428 * *(float *)(DAT_803de1b8 + 0x2c));
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
    iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e2438) * lbl_803DC074
                  * lbl_803E2434 +
                 (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e2438));
    local_48 = (longlong)iVar1;
    param_1[2] = (short)iVar1;
    FUN_800068f4((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80107ee0
 * EN v1.0 Address: 0x80107EE0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010821C
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80107ee0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80107ee4
 * EN v1.0 Address: 0x80107EE4
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x801082AC
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80107ee4(int param_1,int param_2)
{
  ushort *puVar1;
  int iVar2;
  float local_28;
  undefined4 local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  if (*(short *)(param_1 + 0x44) == 1) {
    FUN_80294d78(param_1,&local_28,&local_24,&local_20);
    if (((param_2 != 0) || (*(float *)(DAT_803de1c0 + 0x120) != local_28)) ||
       (*(float *)(DAT_803de1c0 + 0x128) != local_20)) {
      *(undefined4 *)(DAT_803de1c0 + 0x130) = local_24;
    }
    *(float *)(DAT_803de1c0 + 0x120) = local_28;
    *(undefined4 *)(DAT_803de1c0 + 0x124) = local_24;
    *(float *)(DAT_803de1c0 + 0x128) = local_20;
  }
  else {
    *(undefined4 *)(DAT_803de1c0 + 0x120) = *(undefined4 *)(param_1 + 0x18);
    *(float *)(DAT_803de1c0 + 0x124) = lbl_803E2440 + *(float *)(param_1 + 0x1c);
    *(undefined4 *)(DAT_803de1c0 + 0x128) = *(undefined4 *)(param_1 + 0x20);
    *(undefined4 *)(DAT_803de1c0 + 0x130) = *(undefined4 *)(DAT_803de1c0 + 0x124);
  }
  puVar1 = (ushort *)FUN_801e1ee4();
  if ((puVar1 != (ushort *)0x0) && (iVar2 = DBbonedust_getState((int)puVar1), iVar2 == 2)) {
    local_1c = *(float *)(param_1 + 0x18) - *(float *)(puVar1 + 0xc);
    local_18 = (lbl_803E2440 + *(float *)(param_1 + 0x1c)) - *(float *)(puVar1 + 0xe);
    local_14 = *(float *)(param_1 + 0x20) - *(float *)(puVar1 + 0x10);
    FUN_80017748(puVar1,&local_1c);
    *(float *)(DAT_803de1c0 + 0x120) = *(float *)(puVar1 + 0xc) + local_1c;
    *(float *)(DAT_803de1c0 + 0x124) = *(float *)(puVar1 + 0xe) + local_18;
    *(float *)(DAT_803de1c0 + 0x128) = *(float *)(puVar1 + 0x10) + local_14;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80108074
 * EN v1.0 Address: 0x80108074
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80108430
 * EN v1.1 Size: 744b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80108074(short *param_1)
{
}


/* Trivial 4b 0-arg blr leaves. */
void CameraModeBike_release(void) {}
void CameraModeBike_initialise(void) {}
