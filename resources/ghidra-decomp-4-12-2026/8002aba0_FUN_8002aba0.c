// Function: FUN_8002aba0
// Entry: 8002aba0
// Size: 348 bytes

void FUN_8002aba0(int param_1)

{
  float fVar1;
  int iVar2;
  int iVar3;
  undefined8 local_20;
  
  if ((*(byte *)(param_1 + 0xe5) & 4) == 0) {
    local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0xef));
    fVar1 = -(FLOAT_803df51c * FLOAT_803dc074 - (float)(local_20 - DOUBLE_803df528));
  }
  else {
    fVar1 = FLOAT_803df51c * FLOAT_803dc074 +
            (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0xef)) - DOUBLE_803df528);
  }
  if (FLOAT_803df50c <= fVar1) {
    if (FLOAT_803df520 < fVar1) {
      fVar1 = FLOAT_803df520 - (fVar1 - FLOAT_803df520);
      *(byte *)(param_1 + 0xe5) = *(byte *)(param_1 + 0xe5) ^ 4;
    }
  }
  else {
    fVar1 = -fVar1;
    *(byte *)(param_1 + 0xe5) = *(byte *)(param_1 + 0xe5) ^ 4;
  }
  *(char *)(param_1 + 0xef) = (char)(int)fVar1;
  if ((((*(byte *)(param_1 + 0xe5) & 8) == 0) &&
      (*(ushort *)(param_1 + 0xe6) = *(short *)(param_1 + 0xe6) - (ushort)DAT_803dc070,
      *(short *)(param_1 + 0xe6) < 1)) && (*(int *)(param_1 + 0xc4) == 0)) {
    FUN_8002a8ec();
  }
  iVar3 = param_1;
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_1 + 0xeb); iVar2 = iVar2 + 1) {
    FUN_8002aba0(*(int *)(iVar3 + 200));
    iVar3 = iVar3 + 4;
  }
  return;
}

