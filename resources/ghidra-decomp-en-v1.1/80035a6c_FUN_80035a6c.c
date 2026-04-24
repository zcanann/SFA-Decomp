// Function: FUN_80035a6c
// Entry: 80035a6c
// Size: 476 bytes

void FUN_80035a6c(int param_1,undefined2 param_2)

{
  double dVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x54);
  if (iVar3 != 0) {
    if ((*(byte *)(iVar3 + 0x62) & 1) != 0) {
      *(undefined2 *)(iVar3 + 0x5a) = param_2;
      dVar1 = DOUBLE_803df5c0;
      uVar2 = (int)*(short *)(iVar3 + 0x5a) ^ 0x80000000;
      *(float *)(iVar3 + 0xc) =
           (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0) *
           (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0);
      *(float *)(iVar3 + 0x28) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      uVar2 = (int)*(short *)(iVar3 + 0x5a) ^ 0x80000000;
      if (*(float *)(iVar3 + 0x28) < (float)((double)CONCAT44(0x43300000,uVar2) - dVar1)) {
        *(float *)(iVar3 + 0x28) = (float)((double)CONCAT44(0x43300000,uVar2) - dVar1);
      }
      *(float *)(iVar3 + 0x2c) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      uVar2 = (int)*(short *)(iVar3 + 0x5a) ^ 0x80000000;
      if (*(float *)(iVar3 + 0x2c) < (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0))
      {
        *(float *)(iVar3 + 0x2c) = (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803df5c0);
      }
    }
    if ((*(byte *)(iVar3 + 0xb6) & 1) != 0) {
      *(undefined2 *)(iVar3 + 100) = param_2;
      *(float *)(iVar3 + 0x30) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      if (*(float *)(iVar3 + 0x30) <
          (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 0x5a) ^ 0x80000000) -
                 DOUBLE_803df5c0)) {
        *(float *)(iVar3 + 0x30) =
             (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 100) ^ 0x80000000) -
                    DOUBLE_803df5c0);
      }
      *(float *)(iVar3 + 0x34) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      if (*(float *)(iVar3 + 0x34) <
          (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 0x5a) ^ 0x80000000) -
                 DOUBLE_803df5c0)) {
        *(float *)(iVar3 + 0x34) =
             (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 100) ^ 0x80000000) -
                    DOUBLE_803df5c0);
      }
    }
    *(undefined4 *)(iVar3 + 0x38) = *(undefined4 *)(iVar3 + 0x2c);
    if (*(float *)(iVar3 + 0x38) < *(float *)(iVar3 + 0x34)) {
      *(float *)(iVar3 + 0x38) = *(float *)(iVar3 + 0x34);
    }
  }
  return;
}

