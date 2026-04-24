// Function: FUN_801a7b10
// Entry: 801a7b10
// Size: 436 bytes

void FUN_801a7b10(int param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  undefined4 local_18;
  undefined auStack20 [12];
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = FUN_8005b2fc((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                       (double)*(float *)(param_1 + 0x14));
  if (iVar3 != -1) {
    FUN_80035df4(param_1,0xe,1,0);
    FUN_80035f20(param_1);
    *(float *)(param_1 + 0x28) = -(FLOAT_803e455c * FLOAT_803db414 - *(float *)(param_1 + 0x28));
    fVar1 = *(float *)(param_1 + 0x24);
    fVar2 = FLOAT_803e4560;
    if ((FLOAT_803e4560 <= fVar1) && (fVar2 = fVar1, FLOAT_803e4564 < fVar1)) {
      fVar2 = FLOAT_803e4564;
    }
    *(float *)(param_1 + 0x24) = fVar2;
    fVar1 = *(float *)(param_1 + 0x28);
    fVar2 = FLOAT_803e4560;
    if ((FLOAT_803e4560 <= fVar1) && (fVar2 = fVar1, FLOAT_803e4564 < fVar1)) {
      fVar2 = FLOAT_803e4564;
    }
    *(float *)(param_1 + 0x28) = fVar2;
    fVar1 = *(float *)(param_1 + 0x24);
    fVar2 = FLOAT_803e4560;
    if ((FLOAT_803e4560 <= fVar1) && (fVar2 = fVar1, FLOAT_803e4564 < fVar1)) {
      fVar2 = FLOAT_803e4564;
    }
    *(float *)(param_1 + 0x24) = fVar2;
    FUN_8002b95c((double)(*(float *)(param_1 + 0x24) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x28) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x2c) * FLOAT_803db414),param_1);
    *(ushort *)(iVar4 + 0x24) = *(ushort *)(iVar4 + 0x24) & 0xff7f;
    iVar3 = FUN_801a78c8((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                         (double)*(float *)(param_1 + 0x14),
                         (double)(float)((double)FLOAT_803e4568 + (double)*(float *)(param_1 + 0x10)
                                        ),param_1,&local_18,auStack20);
    if (iVar3 != 0) {
      if (iVar3 == 2) {
        *(ushort *)(iVar4 + 0x24) = *(ushort *)(iVar4 + 0x24) | 0x100;
        fVar1 = FLOAT_803e4554;
        *(float *)(param_1 + 0x24) = FLOAT_803e4554;
        *(float *)(param_1 + 0x28) = fVar1;
        *(float *)(param_1 + 0x2c) = fVar1;
      }
      else {
        *(ushort *)(iVar4 + 0x24) = *(ushort *)(iVar4 + 0x24) | 0x180;
        *(undefined4 *)(param_1 + 0x10) = local_18;
        fVar1 = FLOAT_803e4554;
        *(float *)(param_1 + 0x24) = FLOAT_803e4554;
        *(float *)(param_1 + 0x28) = fVar1;
        *(float *)(param_1 + 0x2c) = fVar1;
      }
    }
  }
  return;
}

