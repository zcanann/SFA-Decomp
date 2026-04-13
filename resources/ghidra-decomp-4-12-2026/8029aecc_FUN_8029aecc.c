// Function: FUN_8029aecc
// Entry: 8029aecc
// Size: 1132 bytes

/* WARNING: Removing unreachable block (ram,0x8029b318) */
/* WARNING: Removing unreachable block (ram,0x8029b310) */
/* WARNING: Removing unreachable block (ram,0x8029aee4) */
/* WARNING: Removing unreachable block (ram,0x8029aedc) */

void FUN_8029aecc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  double dVar2;
  short *psVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  float *in_r6;
  undefined4 *in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  int in_r10;
  int *piVar8;
  int iVar9;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  double in_f30;
  double dVar10;
  double in_f31;
  double dVar11;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar12;
  undefined auStack_78 [6];
  undefined2 local_72;
  float local_70;
  float fStack_6c;
  undefined4 uStack_68;
  float fStack_64;
  undefined auStack_60 [12];
  float fStack_54;
  undefined4 uStack_50;
  float afStack_4c [2];
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar12 = FUN_8028683c();
  fVar1 = FLOAT_803e8b3c;
  psVar3 = (short *)((ulonglong)uVar12 >> 0x20);
  iVar6 = (int)uVar12;
  iVar9 = *(int *)(psVar3 + 0x5c);
  if (*(int *)(iVar6 + 0x2d0) == 0) {
    *(float *)(iVar6 + 0x294) = FLOAT_803e8b3c;
    *(float *)(iVar6 + 0x284) = fVar1;
    *(float *)(iVar6 + 0x280) = fVar1;
    *(float *)(psVar3 + 0x12) = fVar1;
    *(float *)(psVar3 + 0x14) = fVar1;
    *(float *)(psVar3 + 0x16) = fVar1;
  }
  iVar4 = FUN_802acf3c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar3,
                       iVar6,iVar9,in_r6,in_r7,in_r8,in_r9,in_r10);
  if (iVar4 == 0) {
    FUN_8011f6d0(6);
    FUN_8011f6ac(10);
    if (DAT_803df0ac != '\0') {
      FUN_8000da78((uint)psVar3,0x382);
      fVar1 = *(float *)(iVar9 + 0x854) - FLOAT_803dc074;
      *(float *)(iVar9 + 0x854) = fVar1;
      if (fVar1 <= FLOAT_803e8b3c) {
        iVar7 = *(int *)(*(int *)(psVar3 + 0x5c) + 0x35c);
        iVar4 = *(short *)(iVar7 + 4) + -1;
        if (iVar4 < 0) {
          iVar4 = 0;
        }
        else if (*(short *)(iVar7 + 6) < iVar4) {
          iVar4 = (int)*(short *)(iVar7 + 6);
        }
        *(short *)(iVar7 + 4) = (short)iVar4;
        *(float *)(iVar9 + 0x854) = FLOAT_803e8bf0;
      }
      FUN_80038524(DAT_803df0cc,5,&fStack_6c,&uStack_68,&fStack_64,0);
      local_70 = FLOAT_803e8c34;
      local_72 = 0;
      (**(code **)(*DAT_803dd708 + 8))(DAT_803df0cc,0x7f5,auStack_78,0x200001,0xffffffff,0);
      local_72 = 1;
      uVar12 = (**(code **)(*DAT_803dd708 + 8))(DAT_803df0cc,0x7f5,auStack_78,0x200001,0xffffffff,0)
      ;
      if ((((*(ushort *)(iVar9 + 0x6e0) & DAT_803df134) == 0) ||
          (*(short *)(*(int *)(*(int *)(psVar3 + 0x5c) + 0x35c) + 4) == 0)) ||
         (iVar4 = FUN_80080490(), uVar12 = extraout_f1_00, iVar4 != 0)) {
        DAT_803df0ac = '\0';
        iVar4 = 0;
        piVar8 = &DAT_80333b34;
        do {
          if (*piVar8 != 0) {
            uVar12 = FUN_8002cc9c(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                  *piVar8);
            *piVar8 = 0;
          }
          piVar8 = piVar8 + 1;
          iVar4 = iVar4 + 1;
        } while (iVar4 < 7);
        if (DAT_803df0d4 != (undefined *)0x0) {
          FUN_80013e4c(DAT_803df0d4);
          DAT_803df0d4 = (undefined *)0x0;
        }
      }
    }
    if (psVar3[0x50] == 0x43f) {
      if (*(int *)(iVar6 + 0x2d0) == 0) {
        *(uint *)(iVar9 + 0x360) = *(uint *)(iVar9 + 0x360) & 0xfffffbff;
        dVar10 = (double)*(float *)(iVar9 + 0x7bc);
        dVar11 = (double)*(float *)(iVar9 + 0x7b8);
        uVar5 = FUN_80070050();
        dVar2 = DOUBLE_803e8b58;
        fVar1 = FLOAT_803e8b30;
        uStack_44 = (int)uVar5 >> 0x11;
        uVar5 = (int)(uVar5 & 0xffff) >> 1 ^ 0x80000000;
        *(float *)(iVar9 + 0x788) =
             FLOAT_803e8b30 *
             (float)(dVar11 * (double)(float)((double)CONCAT44(0x43300000,uVar5) - DOUBLE_803e8b58))
             + (float)((double)CONCAT44(0x43300000,uVar5) - DOUBLE_803e8b58);
        if ((double)FLOAT_803e8b3c <= dVar10) {
          *(float *)(iVar9 + 0x78c) =
               FLOAT_803e8bdc *
               (float)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,uStack_44 ^ 0x80000000)
                                               - dVar2)) +
               (float)((double)CONCAT44(0x43300000,uStack_44 ^ 0x80000000) - dVar2);
        }
        else {
          *(float *)(iVar9 + 0x78c) =
               fVar1 * (float)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,
                                                                         uStack_44 ^ 0x80000000) -
                                                       dVar2)) +
               (float)((double)CONCAT44(0x43300000,uStack_44 ^ 0x80000000) - dVar2);
        }
        uStack_44 = uStack_44 ^ 0x80000000;
        local_40 = 0x43300000;
        afStack_4c[1] = 176.0;
        *(uint *)(iVar9 + 0x360) = *(uint *)(iVar9 + 0x360) | 0x400;
        uStack_3c = uStack_44;
        if (*(char *)(iVar6 + 0x346) != '\0') {
          *(code **)(iVar6 + 0x308) = FUN_8029ac08;
          goto LAB_8029b310;
        }
      }
    }
    else {
      FUN_80038524(DAT_803df0cc,0,&fStack_54,&uStack_50,afStack_4c,0);
      iVar4 = 0;
      do {
        (**(code **)(*DAT_803dd708 + 8))(DAT_803df0cc,0x3ed,auStack_60,0x200001,0xffffffff,0);
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0x28);
      iVar7 = *(int *)(*(int *)(psVar3 + 0x5c) + 0x35c);
      iVar4 = *(short *)(iVar7 + 4) + -2;
      if (iVar4 < 0) {
        iVar4 = 0;
      }
      else if (*(short *)(iVar7 + 6) < iVar4) {
        iVar4 = (int)*(short *)(iVar7 + 6);
      }
      *(short *)(iVar7 + 4) = (short)iVar4;
      FUN_802aac10((double)*(float *)(iVar9 + 0x7bc),param_2,param_3,param_4,param_5,param_6,param_7
                   ,param_8);
      if (*(int *)(iVar6 + 0x2d0) == 0) {
        *(code **)(iVar6 + 0x308) = FUN_8029ac08;
        goto LAB_8029b310;
      }
      FLOAT_803df0e0 = FLOAT_803e8b3c;
      FLOAT_803df0e4 = FLOAT_803e8b3c;
    }
    if ((*(int *)(iVar6 + 0x2d0) == 0) &&
       (((*(ushort *)(iVar9 + 0x6e2) & 0x200) != 0 || (*(char *)(iVar9 + 0x8c8) != 'R')))) {
      *(code **)(iVar6 + 0x308) = FUN_8029ab80;
    }
  }
LAB_8029b310:
  FUN_80286888();
  return;
}

