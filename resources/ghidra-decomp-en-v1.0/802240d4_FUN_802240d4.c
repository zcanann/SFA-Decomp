// Function: FUN_802240d4
// Entry: 802240d4
// Size: 436 bytes

void FUN_802240d4(int param_1)

{
  float fVar1;
  short sVar2;
  int iVar3;
  float *pfVar4;
  float local_28 [2];
  undefined4 local_20;
  uint uStack28;
  longlong local_18;
  
  pfVar4 = *(float **)(param_1 + 0xb8);
  if ((*(byte *)((int)pfVar4 + 10) & 1) == 0) {
    uStack28 = (int)*(short *)(pfVar4 + 2) ^ 0x80000000;
    local_20 = 0x43300000;
    iVar3 = (int)((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e6d48) - FLOAT_803db414)
    ;
    local_18 = (longlong)iVar3;
    sVar2 = (short)iVar3;
    *(short *)(pfVar4 + 2) = sVar2;
    if (sVar2 < 1) {
      local_28[0] = FLOAT_803e6d20;
      iVar3 = FUN_80036e58(3,param_1,local_28);
      fVar1 = FLOAT_803e6d24;
      if (((iVar3 != 0) && (fVar1 = FLOAT_803e6d2c, FLOAT_803e6d28 <= local_28[0])) &&
         (fVar1 = FLOAT_803e6d24, local_28[0] <= FLOAT_803e6d30)) {
        fVar1 = (FLOAT_803e6d38 - (local_28[0] - FLOAT_803e6d28) / FLOAT_803e6d34) * FLOAT_803e6d2c;
      }
      *(float *)(param_1 + 0x28) = fVar1;
      *(byte *)((int)pfVar4 + 10) = *(byte *)((int)pfVar4 + 10) | 1;
      *(undefined *)((int)pfVar4 + 0xb) = 0;
    }
  }
  else {
    *(float *)(param_1 + 0x28) = FLOAT_803e6d3c * FLOAT_803db414 + *(float *)(param_1 + 0x28);
    *(float *)(param_1 + 0x10) =
         *(float *)(param_1 + 0x28) * FLOAT_803db414 + *(float *)(param_1 + 0x10);
    fVar1 = *(float *)(param_1 + 0x10);
    if (fVar1 <= *pfVar4) {
      *(float *)(param_1 + 0x10) = fVar1 + (*pfVar4 - fVar1);
      *(float *)(param_1 + 0x28) = FLOAT_803e6d40 * -*(float *)(param_1 + 0x28);
      *(char *)((int)pfVar4 + 0xb) = *(char *)((int)pfVar4 + 0xb) + '\x01';
      if (10 < *(byte *)((int)pfVar4 + 0xb)) {
        *(byte *)((int)pfVar4 + 10) = *(byte *)((int)pfVar4 + 10) & 0xfe;
        *(undefined2 *)(pfVar4 + 2) = 0x28;
        *(float *)(param_1 + 0x10) = *pfVar4;
        *(float *)(param_1 + 0x28) = FLOAT_803e6d24;
      }
    }
  }
  return;
}

