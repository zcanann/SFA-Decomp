// Function: FUN_801a80c4
// Entry: 801a80c4
// Size: 436 bytes

void FUN_801a80c4(int param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  float local_18;
  undefined4 auStack_14 [3];
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = FUN_8005b478((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
  if (iVar3 != -1) {
    FUN_80035eec(param_1,0xe,1,0);
    FUN_80036018(param_1);
    *(float *)(param_1 + 0x28) = -(FLOAT_803e51f4 * FLOAT_803dc074 - *(float *)(param_1 + 0x28));
    fVar1 = *(float *)(param_1 + 0x24);
    fVar2 = FLOAT_803e51f8;
    if ((FLOAT_803e51f8 <= fVar1) && (fVar2 = fVar1, FLOAT_803e51fc < fVar1)) {
      fVar2 = FLOAT_803e51fc;
    }
    *(float *)(param_1 + 0x24) = fVar2;
    fVar1 = *(float *)(param_1 + 0x28);
    fVar2 = FLOAT_803e51f8;
    if ((FLOAT_803e51f8 <= fVar1) && (fVar2 = fVar1, FLOAT_803e51fc < fVar1)) {
      fVar2 = FLOAT_803e51fc;
    }
    *(float *)(param_1 + 0x28) = fVar2;
    fVar1 = *(float *)(param_1 + 0x24);
    fVar2 = FLOAT_803e51f8;
    if ((FLOAT_803e51f8 <= fVar1) && (fVar2 = fVar1, FLOAT_803e51fc < fVar1)) {
      fVar2 = FLOAT_803e51fc;
    }
    *(float *)(param_1 + 0x24) = fVar2;
    FUN_8002ba34((double)(*(float *)(param_1 + 0x24) * FLOAT_803dc074),
                 (double)(*(float *)(param_1 + 0x28) * FLOAT_803dc074),
                 (double)(*(float *)(param_1 + 0x2c) * FLOAT_803dc074),param_1);
    *(ushort *)(iVar4 + 0x24) = *(ushort *)(iVar4 + 0x24) & 0xff7f;
    iVar3 = FUN_801a7e7c((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                         (double)*(float *)(param_1 + 0x14),
                         (double)(float)((double)FLOAT_803e5200 + (double)*(float *)(param_1 + 0x10)
                                        ),param_1,&local_18,auStack_14);
    if (iVar3 != 0) {
      if (iVar3 == 2) {
        *(ushort *)(iVar4 + 0x24) = *(ushort *)(iVar4 + 0x24) | 0x100;
        fVar1 = FLOAT_803e51ec;
        *(float *)(param_1 + 0x24) = FLOAT_803e51ec;
        *(float *)(param_1 + 0x28) = fVar1;
        *(float *)(param_1 + 0x2c) = fVar1;
      }
      else {
        *(ushort *)(iVar4 + 0x24) = *(ushort *)(iVar4 + 0x24) | 0x180;
        *(float *)(param_1 + 0x10) = local_18;
        fVar1 = FLOAT_803e51ec;
        *(float *)(param_1 + 0x24) = FLOAT_803e51ec;
        *(float *)(param_1 + 0x28) = fVar1;
        *(float *)(param_1 + 0x2c) = fVar1;
      }
    }
  }
  return;
}

