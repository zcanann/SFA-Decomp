#include "ghidra_import.h"
#include "main/dll/CAM/dll_5F.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_8000e054();
extern double FUN_80010c84();
extern double FUN_80010f00();
extern undefined4 FUN_80014e9c();
extern int FUN_80021884();
extern undefined4 FUN_80023d8c();
extern undefined4 FUN_8010a3a0();
extern undefined4 pathcam_buildWindowSamples();
extern undefined8 pathcam_findTaggedNodeWindow();
extern double FUN_8010aee4();
extern uint FUN_8010b144();
extern undefined4 FUN_8010b4d4();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80293900();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803de1d8;
extern f64 DOUBLE_803e2520;
extern f32 FLOAT_803e2508;
extern f32 FLOAT_803e250c;
extern f32 FLOAT_803e253c;

/*
 * --INFO--
 *
 * Function: FUN_8010b6c0
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8010B6C0
 * EN v1.1 Size: 1652b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010b6c0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  byte bVar2;
  short *psVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  uint uVar7;
  undefined4 in_r6;
  float *pfVar8;
  undefined4 in_r7;
  float *pfVar9;
  undefined4 in_r8;
  float *pfVar10;
  undefined4 in_r9;
  float *pfVar11;
  undefined4 in_r10;
  float *pfVar12;
  int iVar13;
  double dVar14;
  undefined8 extraout_f1;
  undefined8 uVar15;
  double dVar16;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 extraout_f1_02;
  undefined8 extraout_f1_03;
  double dVar17;
  double dVar18;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float afStack_108 [4];
  float afStack_f8 [4];
  float afStack_e8 [4];
  float afStack_d8 [4];
  float afStack_c8 [4];
  float afStack_b8 [4];
  float afStack_a8 [4];
  int local_98 [2];
  int local_90;
  int local_8c;
  int local_88 [2];
  int local_80;
  int local_7c;
  undefined8 local_78;
  undefined4 local_70;
  uint uStack_6c;
  longlong local_68;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  psVar3 = (short *)FUN_8028683c();
  if (*(char *)((int)DAT_803de1d8 + 0x65) == '\0') {
    iVar13 = *(int *)(psVar3 + 0x52);
    FUN_80014e9c(0);
    uVar4 = (**(code **)(*DAT_803dd71c + 0x1c))(DAT_803de1d8[3]);
    uVar5 = (**(code **)(*DAT_803dd71c + 0x1c))(DAT_803de1d8[2]);
    uVar15 = pathcam_findTaggedNodeWindow(extraout_f1,param_2,param_3,param_4,param_5,param_6,
                                          param_7,param_8,uVar5,local_98,DAT_803de1d8[1],in_r6,
                                          in_r7,in_r8,in_r9,in_r10);
    pathcam_findTaggedNodeWindow(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 uVar4,local_88,DAT_803de1d8[1],in_r6,in_r7,in_r8,in_r9,in_r10);
    pfVar8 = afStack_c8;
    pfVar9 = afStack_d8;
    pfVar10 = afStack_e8;
    pfVar11 = afStack_f8;
    pfVar12 = afStack_108;
    pathcam_buildWindowSamples(local_98,afStack_a8,afStack_b8,pfVar8,pfVar9,pfVar10,pfVar11,
                               pfVar12);
    dVar17 = (double)*(float *)(iVar13 + 0x1c);
    dVar18 = (double)*(float *)(iVar13 + 0x20);
    dVar16 = FUN_8010aee4((double)*(float *)(iVar13 + 0x18),dVar17,dVar18,local_88);
    dVar14 = (double)FLOAT_803e2508;
    if (dVar14 <= dVar16) {
      dVar14 = dVar16;
      if ((double)FLOAT_803e250c < dVar16) {
        if ((local_80 < 0) || (local_7c < 0)) {
          dVar14 = (double)FLOAT_803e250c;
        }
        else {
          DAT_803de1d8[3] = local_80;
          uVar4 = (**(code **)(*DAT_803dd71c + 0x1c))(DAT_803de1d8[3]);
          pathcam_findTaggedNodeWindow(extraout_f1_02,dVar17,dVar18,param_4,param_5,param_6,param_7,
                                       param_8,uVar4,local_88,DAT_803de1d8[1],pfVar8,pfVar9,
                                       pfVar10,pfVar11,pfVar12);
          if ((local_90 < 0) || (local_8c < 0)) {
            dVar14 = (double)FLOAT_803e250c;
          }
          else {
            DAT_803de1d8[2] = local_90;
            uVar4 = (**(code **)(*DAT_803dd71c + 0x1c))(DAT_803de1d8[2]);
            pathcam_findTaggedNodeWindow(extraout_f1_03,dVar17,dVar18,param_4,param_5,param_6,
                                         param_7,param_8,uVar4,local_98,DAT_803de1d8[1],pfVar8,
                                         pfVar9,pfVar10,pfVar11,pfVar12);
            pathcam_buildWindowSamples(local_98,afStack_a8,afStack_b8,afStack_c8,afStack_d8,
                                       afStack_e8,afStack_f8,afStack_108);
            dVar14 = FUN_8010aee4((double)*(float *)(iVar13 + 0x18),
                                  (double)*(float *)(iVar13 + 0x1c),
                                  (double)*(float *)(iVar13 + 0x20),local_88);
            DAT_803de1d8[0x16] = (int)((float)DAT_803de1d8[0x16] - FLOAT_803e250c);
          }
        }
      }
    }
    else if (-1 < local_88[0]) {
      DAT_803de1d8[3] = local_88[0];
      uVar4 = (**(code **)(*DAT_803dd71c + 0x1c))(DAT_803de1d8[3]);
      pathcam_findTaggedNodeWindow(extraout_f1_00,dVar17,dVar18,param_4,param_5,param_6,param_7,
                                   param_8,uVar4,local_88,DAT_803de1d8[1],pfVar8,pfVar9,pfVar10,
                                   pfVar11,pfVar12);
      if (local_98[0] < 0) {
        dVar14 = (double)FLOAT_803e2508;
      }
      else {
        DAT_803de1d8[2] = local_98[0];
        uVar4 = (**(code **)(*DAT_803dd71c + 0x1c))(DAT_803de1d8[2]);
        pathcam_findTaggedNodeWindow(extraout_f1_01,dVar17,dVar18,param_4,param_5,param_6,param_7,
                                     param_8,uVar4,local_98,DAT_803de1d8[1],pfVar8,pfVar9,
                                     pfVar10,pfVar11,pfVar12);
        pathcam_buildWindowSamples(local_98,afStack_a8,afStack_b8,afStack_c8,afStack_d8,afStack_e8,
                                   afStack_f8,afStack_108);
        dVar14 = FUN_8010aee4((double)*(float *)(iVar13 + 0x18),(double)*(float *)(iVar13 + 0x1c),
                              (double)*(float *)(iVar13 + 0x20),local_88);
        DAT_803de1d8[0x16] = (int)((float)DAT_803de1d8[0x16] + FLOAT_803e250c);
      }
    }
    fVar1 = (float)((double)FLOAT_803e253c *
                    (double)(float)(dVar14 - (double)(float)DAT_803de1d8[0x16]) +
                   (double)(float)DAT_803de1d8[0x16]);
    dVar16 = (double)fVar1;
    DAT_803de1d8[0x16] = (int)fVar1;
    dVar14 = FUN_80010f00(dVar16,afStack_a8,(float *)0x0);
    *(float *)(psVar3 + 0xc) = (float)dVar14;
    dVar14 = FUN_80010f00(dVar16,afStack_b8,(float *)0x0);
    *(float *)(psVar3 + 0xe) = (float)dVar14;
    dVar14 = FUN_80010f00(dVar16,afStack_c8,(float *)0x0);
    *(float *)(psVar3 + 0x10) = (float)dVar14;
    iVar6 = (**(code **)(*DAT_803dd71c + 0x1c))(DAT_803de1d8[2]);
    bVar2 = *(byte *)(iVar6 + 0x3b);
    if ((bVar2 & 1) == 0) {
      dVar14 = FUN_80010c84(dVar16,afStack_d8,(float *)0x0);
      local_78 = (double)(longlong)(int)dVar14;
      *psVar3 = (short)(int)dVar14 + -0x8000;
    }
    if ((bVar2 & 2) == 0) {
      dVar14 = FUN_80010c84(dVar16,afStack_e8,(float *)0x0);
      local_78 = (double)(longlong)(int)dVar14;
      psVar3[1] = (short)(int)dVar14;
    }
    if ((bVar2 & 4) == 0) {
      dVar14 = FUN_80010c84(dVar16,afStack_f8,(float *)0x0);
      local_78 = (double)(longlong)(int)dVar14;
      psVar3[2] = (short)(int)dVar14;
    }
    dVar14 = FUN_80010f00(dVar16,afStack_108,(float *)0x0);
    *(float *)(psVar3 + 0x5a) = (float)dVar14;
    if ((*(char *)(DAT_803de1d8 + 0x19) == '\0') &&
       (uVar7 = FUN_8010b144(psVar3,(uint)bVar2), uVar7 != 0)) {
      *(undefined *)(DAT_803de1d8 + 0x19) = 1;
    }
    dVar17 = (double)(*(float *)(psVar3 + 0xc) - *(float *)(iVar13 + 0x18));
    dVar14 = (double)(*(float *)(psVar3 + 0x10) - *(float *)(iVar13 + 0x20));
    if ((bVar2 & 1) != 0) {
      iVar6 = FUN_80021884();
      *psVar3 = -0x8000 - (short)iVar6;
    }
    if ((bVar2 & 2) != 0) {
      FUN_80293900((double)(float)(dVar17 * dVar17 + (double)(float)(dVar14 * dVar14)));
      uVar7 = FUN_80021884();
      dVar14 = FUN_80010c84(dVar16,afStack_e8,(float *)0x0);
      local_78 = (double)CONCAT44(0x43300000,uVar7 & 0xffff ^ 0x80000000);
      uStack_6c = (ushort)psVar3[1] ^ 0x80000000;
      local_70 = 0x43300000;
      iVar6 = (int)((float)((double)(float)(local_78 - DOUBLE_803e2520) - dVar14) -
                   (float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e2520));
      local_68 = (longlong)iVar6;
      if (0x8000 < iVar6) {
        iVar6 = iVar6 + -0xffff;
      }
      if (iVar6 < -0x8000) {
        iVar6 = iVar6 + 0xffff;
      }
      psVar3[1] = psVar3[1] + (short)((int)(iVar6 * (uint)DAT_803dc070) >> 3);
    }
    if ((bVar2 & 4) != 0) {
      iVar13 = (int)psVar3[2] - (uint)*(ushort *)(iVar13 + 4);
      if (0x8000 < iVar13) {
        iVar13 = iVar13 + -0xffff;
      }
      if (iVar13 < -0x8000) {
        iVar13 = iVar13 + 0xffff;
      }
      psVar3[2] = psVar3[2] + (short)((int)(iVar13 * (uint)DAT_803dc070) >> 3);
    }
    if (*DAT_803de1d8 != 0) {
      uVar4 = *(undefined4 *)(psVar3 + 0xc);
      *(undefined4 *)(*DAT_803de1d8 + 0x18) = uVar4;
      *(undefined4 *)(*DAT_803de1d8 + 0xc) = uVar4;
      uVar4 = *(undefined4 *)(psVar3 + 0xe);
      *(undefined4 *)(*DAT_803de1d8 + 0x1c) = uVar4;
      *(undefined4 *)(*DAT_803de1d8 + 0x10) = uVar4;
      uVar4 = *(undefined4 *)(psVar3 + 0x10);
      *(undefined4 *)(*DAT_803de1d8 + 0x20) = uVar4;
      *(undefined4 *)(*DAT_803de1d8 + 0x14) = uVar4;
    }
    FUN_8000e054((double)*(float *)(psVar3 + 0xc),(double)*(float *)(psVar3 + 0xe),
                 (double)*(float *)(psVar3 + 0x10),(float *)(psVar3 + 6),(float *)(psVar3 + 8),
                 (float *)(psVar3 + 10),*(int *)(psVar3 + 0x18));
  }
  else {
    (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0,0xff);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010bd34
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8010BD34
 * EN v1.1 Size: 1128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010bd34(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
}
