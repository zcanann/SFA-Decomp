// Function: FUN_8014f6e0
// Entry: 8014f6e0
// Size: 680 bytes

/* WARNING: Removing unreachable block (ram,0x8014f964) */
/* WARNING: Removing unreachable block (ram,0x8014f6f0) */

void FUN_8014f6e0(short *param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  double dVar4;
  double dVar5;
  uint uStack_58;
  int iStack_54;
  undefined4 uStack_50;
  undefined4 uStack_4c;
  undefined4 uStack_48;
  undefined4 uStack_44;
  float local_40;
  float local_3c;
  float local_38;
  undefined4 local_30;
  uint uStack_2c;
  longlong local_28;
  
  piVar3 = *(int **)(param_1 + 0x5c);
  iVar2 = *piVar3;
  iVar1 = FUN_80036868((int)param_1,&uStack_44,&iStack_54,&uStack_58,&uStack_48,&uStack_4c,
                       &uStack_50);
  if (iVar1 != 0) {
    piVar3[6] = (int)FLOAT_803e3348;
  }
  FUN_80035eec((int)param_1,10,1,0);
  FUN_80036018((int)param_1);
  if (FLOAT_803e334c < (float)piVar3[6]) {
    piVar3[6] = (int)((float)piVar3[6] - FLOAT_803e3350);
  }
  dVar5 = (double)(float)piVar3[6];
  uStack_2c = (int)*(short *)((int)piVar3 + 0x1e) + (int)*(short *)(piVar3 + 8) ^ 0x80000000;
  local_30 = 0x43300000;
  dVar4 = (double)FUN_802945e0();
  local_28 = (longlong)(int)((double)FLOAT_803e3354 * dVar5);
  FUN_8000b8a8((double)(float)((double)FLOAT_803e3358 * dVar4 + dVar5),(int)param_1,0x40,
               (byte)(int)((double)FLOAT_803e3354 * dVar5));
  (**(code **)(*DAT_803dd708 + 8))(param_1,0x336,0,2,0xffffffff,piVar3 + 6);
  iVar1 = FUN_8002bac4();
  piVar3[1] = iVar1;
  iVar1 = piVar3[1];
  if (iVar1 != 0) {
    local_40 = *(float *)(iVar1 + 0x18) - *(float *)(param_1 + 0xc);
    local_3c = *(float *)(iVar1 + 0x1c) - *(float *)(param_1 + 0xe);
    local_38 = *(float *)(iVar1 + 0x20) - *(float *)(param_1 + 0x10);
    dVar4 = FUN_80293900((double)(local_38 * local_38 + local_40 * local_40 + local_3c * local_3c));
    piVar3[3] = (int)(float)dVar4;
  }
  if (iVar2 != 0) {
    local_40 = *(float *)(iVar2 + 0x68) - *(float *)(param_1 + 0xc);
    local_3c = *(float *)(iVar2 + 0x6c) - *(float *)(param_1 + 0xe);
    local_38 = *(float *)(iVar2 + 0x70) - *(float *)(param_1 + 0x10);
    dVar4 = FUN_80293900((double)(local_38 * local_38 + local_40 * local_40 + local_3c * local_3c));
    piVar3[4] = (int)(float)dVar4;
  }
  if (((*(byte *)(piVar3 + 7) & 2) != 0) && (FLOAT_803e335c < (float)piVar3[4])) {
    *(byte *)(piVar3 + 7) = *(byte *)(piVar3 + 7) & 0xfd;
    *(byte *)(piVar3 + 7) = *(byte *)(piVar3 + 7) | 4;
  }
  if (((*(byte *)(piVar3 + 7) & 4) != 0) && ((float)piVar3[4] < FLOAT_803e3360)) {
    *(byte *)(piVar3 + 7) = *(byte *)(piVar3 + 7) & 0xfb;
  }
  if ((((*(byte *)(piVar3 + 7) & 6) == 0) && (piVar3[1] != 0)) &&
     ((float)piVar3[3] < (float)piVar3[5])) {
    *(byte *)(piVar3 + 7) = *(byte *)(piVar3 + 7) | 2;
  }
  FUN_8014f320(param_1,piVar3);
  return;
}

