// Function: FUN_801c9c14
// Entry: 801c9c14
// Size: 1492 bytes

/* WARNING: Removing unreachable block (ram,0x801ca1c8) */
/* WARNING: Removing unreachable block (ram,0x801ca1c0) */
/* WARNING: Removing unreachable block (ram,0x801ca1b8) */
/* WARNING: Removing unreachable block (ram,0x801ca1b0) */
/* WARNING: Removing unreachable block (ram,0x801c9c3c) */
/* WARNING: Removing unreachable block (ram,0x801c9c34) */
/* WARNING: Removing unreachable block (ram,0x801c9c2c) */
/* WARNING: Removing unreachable block (ram,0x801c9c24) */

void FUN_801c9c14(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  uint uVar2;
  uint uVar3;
  byte bVar6;
  int iVar4;
  uint uVar5;
  int *piVar7;
  int iVar8;
  double in_f28;
  double dVar9;
  double in_f29;
  double dVar10;
  double in_f30;
  double dVar11;
  double in_f31;
  double dVar12;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_78;
  int local_74 [3];
  undefined8 local_68;
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
  uVar2 = FUN_8028683c();
  piVar7 = *(int **)(uVar2 + 0xb8);
  uVar3 = FUN_8002bac4();
  FUN_8000b9bc((double)FLOAT_803e5d78,uVar2,0x3af,10);
  FUN_8000da78(uVar2,0x3af);
  *(undefined *)(param_11 + 0x56) = 0;
  for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar8 = iVar8 + 1) {
    if (*(char *)(param_11 + iVar8 + 0x81) == '\x01') {
      FUN_800146e8(0x1d,0x3c);
      FUN_800146c8();
      *(byte *)(piVar7 + 8) = *(byte *)(piVar7 + 8) & 0xbf;
      *(uint *)(*(int *)(uVar2 + 100) + 0x30) = *(uint *)(*(int *)(uVar2 + 100) + 0x30) | 4;
    }
  }
  if ((*(byte *)(piVar7 + 8) >> 6 & 1) == 0) {
    if (*piVar7 == 0) {
      iVar8 = FUN_8002e1f4(local_74,&local_78);
      while ((local_74[0] < local_78 &&
             (*piVar7 = *(int *)(iVar8 + local_74[0] * 4), *(short *)(*piVar7 + 0x46) != 0x20f))) {
        local_74[0] = local_74[0] + 1;
      }
    }
    if (*piVar7 != 0) {
      dVar10 = (double)FLOAT_803e5d80;
      dVar12 = (double)FLOAT_803e5d90;
      dVar9 = (double)FLOAT_803e5d98;
      dVar11 = DOUBLE_803e5da8;
      for (iVar8 = 0; iVar8 < (int)(uint)DAT_803dc070; iVar8 = iVar8 + 1) {
        bVar6 = FUN_8001469c();
        if (bVar6 != 0) {
          FUN_8000bb38(uVar2,0x1d4);
          *(byte *)(piVar7 + 8) = *(byte *)(piVar7 + 8) & 0x7f;
          *(byte *)(piVar7 + 8) = *(byte *)(piVar7 + 8) & 0xbf | 0x40;
          (**(code **)(*DAT_803dd6d4 + 0x58))(param_11,0xbd);
        }
        uVar5 = FUN_80014e40(0);
        if ((uVar5 & 0x100) != 0) {
          piVar7[1] = (int)((float)piVar7[1] + FLOAT_803e5d7c);
        }
        if (dVar10 < (double)(float)piVar7[1]) {
          piVar7[1] = (int)(float)dVar10;
        }
        local_74[2] = piVar7[4] ^ 0x80000000;
        local_74[1] = 0x43300000;
        iVar4 = (int)((float)((double)CONCAT44(0x43300000,local_74[2]) - dVar11) + (float)piVar7[1])
        ;
        local_68 = (double)(longlong)iVar4;
        piVar7[4] = iVar4;
        if (0x7ef3 < piVar7[4]) {
          FUN_800146a8();
          FUN_8000bb38(uVar2,0x1d4);
          FUN_8003042c((double)FLOAT_803e5d84,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,uVar3,0,0,param_12,param_13,param_14,param_15,param_16);
          *(byte *)(piVar7 + 8) = *(byte *)(piVar7 + 8) & 0x7f | 0x80;
          *(byte *)(piVar7 + 8) = *(byte *)(piVar7 + 8) & 0xbf | 0x40;
          piVar7[4] = 0x7ef4;
          (**(code **)(*DAT_803dd6d4 + 0x58))(param_11,0xbd);
          goto LAB_801ca1b0;
        }
        (**(code **)(*DAT_803dd6d4 + 0x74))(piVar7[6]);
        if (piVar7[4] < 0) {
          piVar7[4] = 0;
          if ((float)piVar7[1] < FLOAT_803e5d84) {
            piVar7[1] = (int)FLOAT_803e5d84;
          }
          piVar7[5] = piVar7[4];
          if (FLOAT_803e5d88 < (float)piVar7[1]) {
            piVar7[1] = (int)((float)piVar7[1] - FLOAT_803e5d8c);
          }
          goto LAB_801ca1b0;
        }
        if (dVar12 < (double)(float)piVar7[1]) {
          piVar7[1] = (int)(float)((double)(float)piVar7[1] - (double)FLOAT_803e5d94);
        }
        local_68 = (double)CONCAT44(0x43300000,piVar7[4] ^ 0x80000000);
        local_74[2] = piVar7[5] ^ 0x80000000;
        local_74[1] = 0x43300000;
        param_2 = (double)FLOAT_803dc074;
        iVar4 = FUN_8002fb40((double)(float)((double)((float)(local_68 - dVar11) -
                                                     (float)((double)CONCAT44(0x43300000,local_74[2]
                                                                             ) - dVar11)) / dVar9),
                             param_2);
        if ((iVar4 != 0) && (*(float *)(uVar3 + 0x98) < FLOAT_803e5d84)) {
          *(float *)(uVar3 + 0x98) = FLOAT_803e5d9c + *(float *)(uVar3 + 0x98);
        }
        if (*piVar7 != 0) {
          local_68 = (double)CONCAT44(0x43300000,piVar7[4] ^ 0x80000000);
          local_74[2] = piVar7[5] ^ 0x80000000;
          local_74[1] = 0x43300000;
          param_2 = (double)FLOAT_803dc074;
          iVar4 = FUN_8002fb40((double)(-((float)(local_68 - DOUBLE_803e5da8) -
                                         (float)((double)CONCAT44(0x43300000,local_74[2]) -
                                                DOUBLE_803e5da8)) / FLOAT_803e5d98),param_2);
          if (iVar4 != 0) {
            fVar1 = *(float *)(*piVar7 + 0x98);
            if (fVar1 < FLOAT_803e5d84) {
              *(float *)(*piVar7 + 0x98) = FLOAT_803e5d9c + fVar1;
            }
          }
        }
        piVar7[5] = piVar7[4];
      }
      piVar7[3] = (int)((float)piVar7[3] - FLOAT_803dc074);
      if ((float)piVar7[3] < FLOAT_803e5d84) {
        if (FLOAT_803e5d84 <= (float)piVar7[1]) {
          uVar5 = FUN_80022264(0x78,0xf0);
          local_68 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          piVar7[3] = (int)(float)(local_68 - DOUBLE_803e5da8);
        }
        else {
          uVar5 = FUN_80022264(0x28,100);
          local_68 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          piVar7[3] = (int)(float)(local_68 - DOUBLE_803e5da8);
        }
        FUN_8000bb38(uVar3,0x13a);
      }
      piVar7[2] = (int)((float)piVar7[2] - FLOAT_803dc074);
      if ((float)piVar7[2] < FLOAT_803e5d84) {
        if ((float)piVar7[1] <= FLOAT_803e5d84) {
          uVar3 = FUN_80022264(0x78,0xf0);
          local_68 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
          piVar7[2] = (int)(float)(local_68 - DOUBLE_803e5da8);
        }
        else {
          uVar3 = FUN_80022264(0x28,100);
          local_68 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
          piVar7[2] = (int)(float)(local_68 - DOUBLE_803e5da8);
        }
        FUN_8000bb38(uVar2,0x4a3);
      }
      fVar1 = FLOAT_803e5da0 * (float)piVar7[1];
      if (fVar1 < FLOAT_803e5d84) {
        fVar1 = -fVar1;
      }
      iVar8 = (int)fVar1;
      local_68 = (double)(longlong)iVar8;
      if (100 < iVar8) {
        iVar8 = 100;
      }
      FUN_8000b9bc((double)FLOAT_803e5d78,uVar2,0x3af,(byte)iVar8);
    }
  }
LAB_801ca1b0:
  FUN_80286888();
  return;
}

