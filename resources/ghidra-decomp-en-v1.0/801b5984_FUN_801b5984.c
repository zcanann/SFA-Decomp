// Function: FUN_801b5984
// Entry: 801b5984
// Size: 156 bytes

void FUN_801b5984(undefined2 *param_1,int param_2)

{
  float fVar1;
  int iVar2;
  undefined *puVar3;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x6000;
  puVar3 = *(undefined **)(param_1 + 0x5c);
  *puVar3 = 3;
  fVar1 = FLOAT_803e49d4;
  *(float *)(puVar3 + 4) = FLOAT_803e49d4;
  *(float *)(puVar3 + 8) = fVar1;
  iVar2 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  if (iVar2 != 0) {
    *puVar3 = 0;
    *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
    *(undefined *)(param_1 + 0x1b) = 0;
  }
  return;
}

