// Function: FUN_801b5f38
// Entry: 801b5f38
// Size: 156 bytes

void FUN_801b5f38(undefined2 *param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  undefined *puVar3;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x6000;
  puVar3 = *(undefined **)(param_1 + 0x5c);
  *puVar3 = 3;
  fVar1 = FLOAT_803e566c;
  *(float *)(puVar3 + 4) = FLOAT_803e566c;
  *(float *)(puVar3 + 8) = fVar1;
  uVar2 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  if (uVar2 != 0) {
    *puVar3 = 0;
    *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  return;
}

