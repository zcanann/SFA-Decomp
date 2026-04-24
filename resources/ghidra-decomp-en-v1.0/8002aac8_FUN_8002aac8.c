// Function: FUN_8002aac8
// Entry: 8002aac8
// Size: 348 bytes

void FUN_8002aac8(int param_1)

{
  float fVar1;
  int iVar2;
  int iVar3;
  double local_20;
  
  if ((*(byte *)(param_1 + 0xe5) & 4) == 0) {
    local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0xef));
    fVar1 = -(FLOAT_803de89c * FLOAT_803db414 - (float)(local_20 - DOUBLE_803de8a8));
  }
  else {
    fVar1 = FLOAT_803de89c * FLOAT_803db414 +
            (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0xef)) - DOUBLE_803de8a8);
  }
  if (FLOAT_803de88c <= fVar1) {
    if (FLOAT_803de8a0 < fVar1) {
      fVar1 = FLOAT_803de8a0 - (fVar1 - FLOAT_803de8a0);
      *(byte *)(param_1 + 0xe5) = *(byte *)(param_1 + 0xe5) ^ 4;
    }
  }
  else {
    fVar1 = -fVar1;
    *(byte *)(param_1 + 0xe5) = *(byte *)(param_1 + 0xe5) ^ 4;
  }
  *(char *)(param_1 + 0xef) = (char)(int)fVar1;
  if ((((*(byte *)(param_1 + 0xe5) & 8) == 0) &&
      (*(ushort *)(param_1 + 0xe6) = *(short *)(param_1 + 0xe6) - (ushort)DAT_803db410,
      *(short *)(param_1 + 0xe6) < 1)) && (*(int *)(param_1 + 0xc4) == 0)) {
    FUN_8002a814(param_1);
  }
  iVar3 = param_1;
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_1 + 0xeb); iVar2 = iVar2 + 1) {
    FUN_8002aac8(*(undefined4 *)(iVar3 + 200));
    iVar3 = iVar3 + 4;
  }
  return;
}

