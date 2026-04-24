// Function: FUN_8014f24c
// Entry: 8014f24c
// Size: 680 bytes

/* WARNING: Removing unreachable block (ram,0x8014f4d0) */

void FUN_8014f24c(int param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f31;
  double dVar6;
  undefined auStack88 [4];
  undefined auStack84 [4];
  undefined auStack80 [4];
  undefined auStack76 [4];
  undefined auStack72 [4];
  undefined auStack68 [4];
  float local_40;
  float local_3c;
  float local_38;
  undefined4 local_30;
  uint uStack44;
  longlong local_28;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  piVar3 = *(int **)(param_1 + 0xb8);
  iVar2 = *piVar3;
  iVar1 = FUN_80036770(param_1,auStack68,auStack84,auStack88,auStack72,auStack76,auStack80);
  if (iVar1 != 0) {
    piVar3[6] = (int)FLOAT_803e26b0;
  }
  FUN_80035df4(param_1,10,1,0);
  FUN_80035f20(param_1);
  if (FLOAT_803e26b4 < (float)piVar3[6]) {
    piVar3[6] = (int)((float)piVar3[6] - FLOAT_803e26b8);
  }
  dVar6 = (double)(float)piVar3[6];
  uStack44 = (int)*(short *)((int)piVar3 + 0x1e) + (int)*(short *)(piVar3 + 8) ^ 0x80000000;
  local_30 = 0x43300000;
  dVar5 = (double)FUN_80293e80((double)((FLOAT_803e26a0 *
                                        (float)((double)CONCAT44(0x43300000,uStack44) -
                                               DOUBLE_803e26a8)) / FLOAT_803e26a4));
  local_28 = (longlong)(int)((double)FLOAT_803e26bc * dVar6);
  FUN_8000b888((double)(float)((double)FLOAT_803e26c0 * dVar5 + dVar6),param_1,0x40,
               (int)((double)FLOAT_803e26bc * dVar6));
  (**(code **)(*DAT_803dca88 + 8))(param_1,0x336,0,2,0xffffffff,piVar3 + 6);
  iVar1 = FUN_8002b9ec();
  piVar3[1] = iVar1;
  iVar1 = piVar3[1];
  if (iVar1 != 0) {
    local_40 = *(float *)(iVar1 + 0x18) - *(float *)(param_1 + 0x18);
    local_3c = *(float *)(iVar1 + 0x1c) - *(float *)(param_1 + 0x1c);
    local_38 = *(float *)(iVar1 + 0x20) - *(float *)(param_1 + 0x20);
    dVar5 = (double)FUN_802931a0((double)(local_38 * local_38 +
                                         local_40 * local_40 + local_3c * local_3c));
    piVar3[3] = (int)(float)dVar5;
  }
  if (iVar2 != 0) {
    local_40 = *(float *)(iVar2 + 0x68) - *(float *)(param_1 + 0x18);
    local_3c = *(float *)(iVar2 + 0x6c) - *(float *)(param_1 + 0x1c);
    local_38 = *(float *)(iVar2 + 0x70) - *(float *)(param_1 + 0x20);
    dVar5 = (double)FUN_802931a0((double)(local_38 * local_38 +
                                         local_40 * local_40 + local_3c * local_3c));
    piVar3[4] = (int)(float)dVar5;
  }
  if (((*(byte *)(piVar3 + 7) & 2) != 0) && (FLOAT_803e26c4 < (float)piVar3[4])) {
    *(byte *)(piVar3 + 7) = *(byte *)(piVar3 + 7) & 0xfd;
    *(byte *)(piVar3 + 7) = *(byte *)(piVar3 + 7) | 4;
  }
  if (((*(byte *)(piVar3 + 7) & 4) != 0) && ((float)piVar3[4] < FLOAT_803e26c8)) {
    *(byte *)(piVar3 + 7) = *(byte *)(piVar3 + 7) & 0xfb;
  }
  if ((((*(byte *)(piVar3 + 7) & 6) == 0) && (piVar3[1] != 0)) &&
     ((float)piVar3[3] < (float)piVar3[5])) {
    *(byte *)(piVar3 + 7) = *(byte *)(piVar3 + 7) | 2;
  }
  FUN_8014ee8c(param_1,piVar3);
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return;
}

