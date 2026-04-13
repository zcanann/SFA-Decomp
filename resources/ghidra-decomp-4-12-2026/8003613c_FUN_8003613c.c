// Function: FUN_8003613c
// Entry: 8003613c
// Size: 1036 bytes

void FUN_8003613c(int param_1)

{
  double dVar1;
  uint uVar2;
  short sVar3;
  short sVar4;
  int iVar5;
  int *piVar6;
  
  iVar5 = *(int *)(param_1 + 0x54);
  if (iVar5 != 0) {
    *(undefined2 *)(iVar5 + 0x60) = *(undefined2 *)(*(int *)(param_1 + 0x50) + 0x4e);
    *(undefined *)(iVar5 + 0x62) = *(undefined *)(*(int *)(param_1 + 0x50) + 0x65);
    if (((*(byte *)(iVar5 + 0x62) & 0x20) != 0) &&
       ((piVar6 = *(int **)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4),
        (*(ushort *)(*piVar6 + 2) & 0x1000) == 0 || (piVar6[5] == 0)))) {
      *(byte *)(iVar5 + 0x62) = *(byte *)(iVar5 + 0x62) & 0xdf;
    }
    *(undefined *)(iVar5 + 0x6a) = *(undefined *)(*(int *)(param_1 + 0x50) + 99);
    *(undefined *)(iVar5 + 0x6b) = *(undefined *)(*(int *)(param_1 + 0x50) + 100);
    *(ushort *)(iVar5 + 0x5a) = (ushort)*(byte *)(*(int *)(param_1 + 0x50) + 0x62);
    *(undefined2 *)(iVar5 + 0x5c) = *(undefined2 *)(*(int *)(param_1 + 0x50) + 0x68);
    *(undefined2 *)(iVar5 + 0x5e) = *(undefined2 *)(*(int *)(param_1 + 0x50) + 0x6a);
    *(undefined *)(iVar5 + 0xb0) = *(undefined *)(*(int *)(param_1 + 0x50) + 0x60);
    *(undefined2 *)(iVar5 + 0x58) = 0x400;
    dVar1 = DOUBLE_803df5c0;
    uVar2 = (int)*(short *)(iVar5 + 0x5a) ^ 0x80000000;
    *(float *)(iVar5 + 0xc) =
         (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0) *
         (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0);
    *(undefined *)(iVar5 + 0xb6) = *(undefined *)(*(int *)(param_1 + 0x50) + 0x90);
    *(ushort *)(iVar5 + 100) = (ushort)*(byte *)(*(int *)(param_1 + 0x50) + 0x77);
    *(undefined2 *)(iVar5 + 0x66) = *(undefined2 *)(*(int *)(param_1 + 0x50) + 0x6c);
    *(undefined2 *)(iVar5 + 0x68) = *(undefined2 *)(*(int *)(param_1 + 0x50) + 0x6e);
    *(float *)(iVar5 + 0x28) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
    if ((*(byte *)(iVar5 + 0x62) & 2) == 0) {
      if ((*(byte *)(iVar5 + 0x62) & 1) != 0) {
        uVar2 = (int)*(short *)(iVar5 + 0x5a) ^ 0x80000000;
        if (*(float *)(iVar5 + 0x28) < (float)((double)CONCAT44(0x43300000,uVar2) - dVar1)) {
          *(float *)(iVar5 + 0x28) = (float)((double)CONCAT44(0x43300000,uVar2) - dVar1);
        }
      }
    }
    else {
      sVar3 = *(short *)(iVar5 + 0x5c);
      if (sVar3 < 0) {
        sVar3 = -sVar3;
      }
      sVar4 = *(short *)(iVar5 + 0x5e);
      if (sVar4 < 0) {
        sVar4 = -sVar4;
      }
      if (sVar4 < sVar3) {
        sVar4 = sVar3;
      }
      if (*(float *)(iVar5 + 0x28) <
          (float)((double)CONCAT44(0x43300000,(int)sVar4 ^ 0x80000000U) - DOUBLE_803df5c0)) {
        *(float *)(iVar5 + 0x28) =
             (float)((double)CONCAT44(0x43300000,(int)sVar4 ^ 0x80000000U) - DOUBLE_803df5c0);
      }
    }
    *(float *)(iVar5 + 0x2c) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
    if (((*(byte *)(iVar5 + 0x62) & 2) != 0) || ((*(byte *)(iVar5 + 0x62) & 1) != 0)) {
      uVar2 = (int)*(short *)(iVar5 + 0x5a) ^ 0x80000000;
      if (*(float *)(iVar5 + 0x2c) < (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0))
      {
        *(float *)(iVar5 + 0x2c) = (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0);
      }
    }
    *(float *)(iVar5 + 0x30) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
    if ((*(byte *)(iVar5 + 0xb6) & 2) == 0) {
      if ((*(byte *)(iVar5 + 0xb6) & 1) != 0) {
        uVar2 = (int)*(short *)(iVar5 + 100) ^ 0x80000000;
        if (*(float *)(iVar5 + 0x30) < (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0)
           ) {
          *(float *)(iVar5 + 0x30) = (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0);
        }
      }
    }
    else {
      sVar3 = *(short *)(iVar5 + 0x66);
      if (sVar3 < 0) {
        sVar3 = -sVar3;
      }
      sVar4 = *(short *)(iVar5 + 0x68);
      if (sVar4 < 0) {
        sVar4 = -sVar4;
      }
      if (sVar4 < sVar3) {
        sVar4 = sVar3;
      }
      if (*(float *)(iVar5 + 0x30) <
          (float)((double)CONCAT44(0x43300000,(int)sVar4 ^ 0x80000000U) - DOUBLE_803df5c0)) {
        *(float *)(iVar5 + 0x30) =
             (float)((double)CONCAT44(0x43300000,(int)sVar4 ^ 0x80000000U) - DOUBLE_803df5c0);
      }
    }
    *(float *)(iVar5 + 0x34) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
    if (((*(byte *)(iVar5 + 0xb6) & 2) != 0) || ((*(byte *)(iVar5 + 0xb6) & 1) != 0)) {
      uVar2 = (int)*(short *)(iVar5 + 100) ^ 0x80000000;
      if (*(float *)(iVar5 + 0x34) < (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0))
      {
        *(float *)(iVar5 + 0x34) = (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0);
      }
    }
    *(undefined4 *)(iVar5 + 0x38) = *(undefined4 *)(iVar5 + 0x2c);
    if (*(float *)(iVar5 + 0x38) < *(float *)(iVar5 + 0x34)) {
      *(float *)(iVar5 + 0x38) = *(float *)(iVar5 + 0x34);
    }
    *(undefined *)(iVar5 + 0xb4) = *(undefined *)(*(int *)(param_1 + 0x50) + 0x70);
    *(undefined *)(iVar5 + 0xb5) = *(undefined *)(*(int *)(param_1 + 0x50) + 0x67);
  }
  return;
}

