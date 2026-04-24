// Function: FUN_801c2914
// Entry: 801c2914
// Size: 852 bytes

/* WARNING: Removing unreachable block (ram,0x801c2c40) */

void FUN_801c2914(short *param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f31;
  undefined auStack152 [32];
  longlong local_78;
  longlong local_70;
  longlong local_68;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  longlong local_48;
  undefined4 local_40;
  uint uStack60;
  double local_38;
  double local_30;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar4 = *(int *)(param_1 + 0x26);
  iVar3 = *(int *)(param_1 + 0x5c);
  iVar1 = FUN_8002b9ec();
  if ((param_1[3] & 0x4000U) == 0) {
    local_78 = (longlong)(int)(FLOAT_803e4e50 * FLOAT_803db414);
    *(short *)(iVar3 + 0x14) =
         *(short *)(iVar3 + 0x14) + (short)(int)(FLOAT_803e4e50 * FLOAT_803db414);
    local_70 = (longlong)(int)(FLOAT_803e4e54 * FLOAT_803db414);
    *(short *)(iVar3 + 0x16) =
         *(short *)(iVar3 + 0x16) + (short)(int)(FLOAT_803e4e54 * FLOAT_803db414);
    local_68 = (longlong)(int)(FLOAT_803e4e58 * FLOAT_803db414);
    *(short *)(iVar3 + 0x18) =
         *(short *)(iVar3 + 0x18) + (short)(int)(FLOAT_803e4e58 * FLOAT_803db414);
    uStack92 = (int)*(short *)(iVar3 + 0x14) ^ 0x80000000;
    local_60 = 0x43300000;
    dVar6 = (double)FUN_80293e80((double)((FLOAT_803e4e60 *
                                          (float)((double)CONCAT44(0x43300000,uStack92) -
                                                 DOUBLE_803e4e80)) / FLOAT_803e4e64));
    *(float *)(param_1 + 8) = FLOAT_803e4e5c + (float)((double)*(float *)(iVar4 + 0xc) + dVar6);
    uStack84 = (int)*(short *)(iVar3 + 0x16) ^ 0x80000000;
    local_58 = 0x43300000;
    dVar6 = (double)FUN_80293e80((double)((FLOAT_803e4e60 *
                                          (float)((double)CONCAT44(0x43300000,uStack84) -
                                                 DOUBLE_803e4e80)) / FLOAT_803e4e64));
    uStack76 = (int)*(short *)(iVar3 + 0x14) ^ 0x80000000;
    local_50 = 0x43300000;
    dVar7 = (double)FUN_80293e80((double)((FLOAT_803e4e60 *
                                          (float)((double)CONCAT44(0x43300000,uStack76) -
                                                 DOUBLE_803e4e80)) / FLOAT_803e4e64));
    iVar4 = (int)(FLOAT_803e4e68 * (float)(dVar7 + dVar6));
    local_48 = (longlong)iVar4;
    param_1[2] = (short)iVar4;
    uStack60 = (int)*(short *)(iVar3 + 0x18) ^ 0x80000000;
    local_40 = 0x43300000;
    dVar6 = (double)FUN_80293e80((double)((FLOAT_803e4e60 *
                                          (float)((double)CONCAT44(0x43300000,uStack60) -
                                                 DOUBLE_803e4e80)) / FLOAT_803e4e64));
    local_38 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 0x14) ^ 0x80000000);
    dVar7 = (double)FUN_80293e80((double)((FLOAT_803e4e60 * (float)(local_38 - DOUBLE_803e4e80)) /
                                         FLOAT_803e4e64));
    iVar3 = (int)(FLOAT_803e4e68 * (float)(dVar7 + dVar6));
    local_30 = (double)(longlong)iVar3;
    param_1[1] = (short)iVar3;
    FUN_8002fa48((double)FLOAT_803e4e6c,(double)FLOAT_803db414,param_1,auStack152);
    if (iVar1 != 0) {
      uVar2 = FUN_800217c0((double)(*(float *)(param_1 + 0xc) - *(float *)(iVar1 + 0x18)),
                           (double)(*(float *)(param_1 + 0x10) - *(float *)(iVar1 + 0x20)));
      uVar2 = (uVar2 & 0xffff) - ((int)*param_1 & 0xffffU);
      if (0x8000 < (int)uVar2) {
        uVar2 = uVar2 - 0xffff;
      }
      if ((int)uVar2 < -0x8000) {
        uVar2 = uVar2 + 0xffff;
      }
      local_30 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      iVar3 = (int)(((float)(local_30 - DOUBLE_803e4e80) * FLOAT_803db414) / FLOAT_803e4e70);
      local_38 = (double)(longlong)iVar3;
      *param_1 = *param_1 + (short)iVar3;
      dVar6 = (double)FUN_80021690(param_1 + 0xc,iVar1 + 0x18);
      if ((double)FLOAT_803e4e74 < dVar6) {
        *(undefined *)(param_1 + 0x1b) = 0xff;
      }
      else {
        *(char *)(param_1 + 0x1b) =
             (char)(int)(FLOAT_803e4e78 * (float)(dVar6 / (double)FLOAT_803e4e74));
      }
    }
  }
  else {
    *param_1 = 0;
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar4 + 0xc);
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return;
}

