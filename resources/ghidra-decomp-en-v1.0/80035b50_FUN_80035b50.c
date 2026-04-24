// Function: FUN_80035b50
// Entry: 80035b50
// Size: 604 bytes

void FUN_80035b50(int param_1,undefined2 param_2,short param_3,short param_4)

{
  float fVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  
  iVar3 = *(int *)(param_1 + 0x54);
  if (iVar3 != 0) {
    if ((*(byte *)(iVar3 + 0x62) & 2) != 0) {
      *(short *)(iVar3 + 0x5c) = param_3;
      *(short *)(iVar3 + 0x5e) = param_4;
      *(undefined2 *)(iVar3 + 0x5a) = param_2;
      uVar4 = (int)*(short *)(iVar3 + 0x5a) ^ 0x80000000;
      *(float *)(iVar3 + 0xc) =
           (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803de940) *
           (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803de940);
      *(undefined2 *)(iVar3 + 0x58) = 0x400;
      *(float *)(iVar3 + 0x28) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      uVar4 = (uint)param_3;
      if ((int)uVar4 < 0) {
        uVar4 = -uVar4;
      }
      fVar1 = (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803de940);
      uVar4 = (uint)param_4;
      if ((int)uVar4 < 0) {
        uVar4 = -uVar4;
      }
      fVar2 = (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803de940);
      if (fVar2 < fVar1) {
        fVar2 = fVar1;
      }
      if (*(float *)(iVar3 + 0x28) < fVar2) {
        *(float *)(iVar3 + 0x28) = fVar2;
      }
      *(float *)(iVar3 + 0x2c) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      uVar4 = (int)*(short *)(iVar3 + 0x5a) ^ 0x80000000;
      if (*(float *)(iVar3 + 0x2c) < (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803de940))
      {
        *(float *)(iVar3 + 0x2c) = (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803de940);
      }
    }
    if ((*(byte *)(iVar3 + 0xb6) & 2) != 0) {
      *(short *)(iVar3 + 0x66) = param_3;
      *(short *)(iVar3 + 0x68) = param_4;
      *(undefined2 *)(iVar3 + 100) = param_2;
      *(float *)(iVar3 + 0x30) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      uVar4 = (uint)param_3;
      if ((int)uVar4 < 0) {
        uVar4 = -uVar4;
      }
      fVar1 = (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803de940);
      uVar4 = (uint)param_4;
      if ((int)uVar4 < 0) {
        uVar4 = -uVar4;
      }
      fVar2 = (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803de940);
      if (fVar2 < fVar1) {
        fVar2 = fVar1;
      }
      if (*(float *)(iVar3 + 0x30) < fVar2) {
        *(float *)(iVar3 + 0x30) = fVar2;
      }
      *(float *)(iVar3 + 0x34) = *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8);
      if (*(float *)(iVar3 + 0x34) <
          (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 0x5a) ^ 0x80000000) -
                 DOUBLE_803de940)) {
        *(float *)(iVar3 + 0x34) =
             (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 100) ^ 0x80000000) -
                    DOUBLE_803de940);
      }
    }
    *(undefined4 *)(iVar3 + 0x38) = *(undefined4 *)(iVar3 + 0x2c);
    if (*(float *)(iVar3 + 0x38) < *(float *)(iVar3 + 0x34)) {
      *(float *)(iVar3 + 0x38) = *(float *)(iVar3 + 0x34);
    }
  }
  return;
}

