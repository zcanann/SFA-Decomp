// Function: FUN_80224724
// Entry: 80224724
// Size: 436 bytes

void FUN_80224724(int param_1)

{
  float fVar1;
  short sVar2;
  int iVar3;
  float *pfVar4;
  float local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  pfVar4 = *(float **)(param_1 + 0xb8);
  if ((*(byte *)((int)pfVar4 + 10) & 1) == 0) {
    uStack_1c = (int)*(short *)(pfVar4 + 2) ^ 0x80000000;
    local_20 = 0x43300000;
    iVar3 = (int)((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e79e0) - FLOAT_803dc074
                 );
    local_18 = (longlong)iVar3;
    sVar2 = (short)iVar3;
    *(short *)(pfVar4 + 2) = sVar2;
    if (sVar2 < 1) {
      local_28[0] = FLOAT_803e79b8;
      iVar3 = FUN_80036f50(3,param_1,local_28);
      fVar1 = FLOAT_803e79bc;
      if (((iVar3 != 0) && (fVar1 = FLOAT_803e79c4, FLOAT_803e79c0 <= local_28[0])) &&
         (fVar1 = FLOAT_803e79bc, local_28[0] <= FLOAT_803e79c8)) {
        fVar1 = (FLOAT_803e79d0 - (local_28[0] - FLOAT_803e79c0) / FLOAT_803e79cc) * FLOAT_803e79c4;
      }
      *(float *)(param_1 + 0x28) = fVar1;
      *(byte *)((int)pfVar4 + 10) = *(byte *)((int)pfVar4 + 10) | 1;
      *(undefined *)((int)pfVar4 + 0xb) = 0;
    }
  }
  else {
    *(float *)(param_1 + 0x28) = FLOAT_803e79d4 * FLOAT_803dc074 + *(float *)(param_1 + 0x28);
    *(float *)(param_1 + 0x10) =
         *(float *)(param_1 + 0x28) * FLOAT_803dc074 + *(float *)(param_1 + 0x10);
    fVar1 = *(float *)(param_1 + 0x10);
    if (fVar1 <= *pfVar4) {
      *(float *)(param_1 + 0x10) = fVar1 + (*pfVar4 - fVar1);
      *(float *)(param_1 + 0x28) = FLOAT_803e79d8 * -*(float *)(param_1 + 0x28);
      *(char *)((int)pfVar4 + 0xb) = *(char *)((int)pfVar4 + 0xb) + '\x01';
      if (10 < *(byte *)((int)pfVar4 + 0xb)) {
        *(byte *)((int)pfVar4 + 10) = *(byte *)((int)pfVar4 + 10) & 0xfe;
        *(undefined2 *)(pfVar4 + 2) = 0x28;
        *(float *)(param_1 + 0x10) = *pfVar4;
        *(float *)(param_1 + 0x28) = FLOAT_803e79bc;
      }
    }
  }
  return;
}

