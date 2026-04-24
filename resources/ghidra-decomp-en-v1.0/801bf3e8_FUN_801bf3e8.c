// Function: FUN_801bf3e8
// Entry: 801bf3e8
// Size: 716 bytes

/* WARNING: Removing unreachable block (ram,0x801bf688) */
/* WARNING: Removing unreachable block (ram,0x801bf690) */

void FUN_801bf3e8(short *param_1)

{
  ushort uVar1;
  int iVar2;
  short sVar3;
  float *pfVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f30;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  undefined4 local_68;
  undefined auStack100 [4];
  undefined auStack96 [4];
  undefined auStack92 [8];
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar5 = *(int *)(param_1 + 0x5c);
  if ((*(int *)(param_1 + 0x7a) == 0) &&
     ((*(int *)(param_1 + 0x18) != 0 ||
      (iVar2 = FUN_8005b2fc((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                            (double)*(float *)(param_1 + 10)), -1 < iVar2)))) {
    local_68 = 0;
    do {
      iVar2 = FUN_800374ec(param_1,auStack100,auStack96,&local_68);
    } while (iVar2 != 0);
    pfVar4 = *(float **)(iVar5 + 0x40c);
    if ((*pfVar4 < FLOAT_803e4cd0) && (pfVar4[4] < FLOAT_803e4cd4)) {
      dVar9 = (double)(pfVar4[3] - *(float *)(param_1 + 8));
      if (dVar9 < (double)FLOAT_803e4cd8) {
        dVar9 = -dVar9;
      }
      if ((dVar9 < (double)FLOAT_803e4cdc) &&
         (local_4c = pfVar4[3], iVar2 = FUN_800221a0(0x1e,0x3c),
         iVar2 < (int)(uint)*(ushort *)((int)pfVar4 + 0x16))) {
        dVar8 = (double)(FLOAT_803e4ce0 * pfVar4[4]);
        uStack60 = (int)*param_1 ^ 0x80000000;
        local_40 = 0x43300000;
        dVar7 = (double)FUN_80293e80((double)((FLOAT_803e4ce4 *
                                              (float)((double)CONCAT44(0x43300000,uStack60) -
                                                     DOUBLE_803e4cf8)) / FLOAT_803e4ce8));
        local_50 = -(float)(dVar8 * dVar7 - (double)*(float *)(param_1 + 6));
        uStack52 = (int)*param_1 ^ 0x80000000;
        local_38 = 0x43300000;
        dVar7 = (double)FUN_80294204((double)((FLOAT_803e4ce4 *
                                              (float)((double)CONCAT44(0x43300000,uStack52) -
                                                     DOUBLE_803e4cf8)) / FLOAT_803e4ce8));
        local_48 = -(float)(dVar8 * dVar7 - (double)*(float *)(param_1 + 10));
        local_54 = FLOAT_803e4cec * (FLOAT_803e4cf0 - (float)(dVar9 / (double)FLOAT_803e4cdc));
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x32b,auStack92,1,0xffffffff,0);
        *(undefined2 *)((int)pfVar4 + 0x16) = 0;
      }
    }
    *(ushort *)((int)pfVar4 + 0x16) = *(short *)((int)pfVar4 + 0x16) + (ushort)DAT_803db410;
    FUN_801beea0(param_1,iVar5);
    FUN_801bf048(param_1,iVar5);
    FUN_8002fa48((double)FLOAT_803e4d20,(double)FLOAT_803db414,param_1,0);
    *(undefined *)(*(int *)(param_1 + 0x2a) + 0x6e) = 9;
    *(undefined *)(*(int *)(param_1 + 0x2a) + 0x6f) = 1;
    FUN_8003393c(param_1);
    iVar2 = *(int *)(iVar5 + 0x40c);
    iVar5 = *(int *)(iVar2 + 0x18);
    if (((iVar5 != 0) && (*(char *)(iVar5 + 0x2f8) != '\0')) && (*(char *)(iVar5 + 0x4c) != '\0')) {
      uVar1 = (ushort)*(byte *)(iVar5 + 0x2f9) + (short)*(char *)(iVar5 + 0x2fa);
      if (0xc < uVar1) {
        sVar3 = FUN_800221a0(0xfffffff4,0xc);
        uVar1 = uVar1 + sVar3;
        if (0xff < uVar1) {
          uVar1 = 0xff;
          *(undefined *)(*(int *)(iVar2 + 0x18) + 0x2fa) = 0;
        }
      }
      *(char *)(*(int *)(iVar2 + 0x18) + 0x2f9) = (char)uVar1;
    }
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  return;
}

