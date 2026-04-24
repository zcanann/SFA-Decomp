// Function: FUN_800e8054
// Entry: 800e8054
// Size: 172 bytes

undefined4 FUN_800e8054(int param_1)

{
  undefined1 *puVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = 0;
  puVar1 = &DAT_803a32a8;
  iVar3 = 0x3f;
  while (*(int *)(*(int *)(param_1 + 0x4c) + 0x14) != *(int *)(puVar1 + 0x168)) {
    puVar1 = puVar1 + 0x10;
    iVar2 = iVar2 + 1;
    iVar3 = iVar3 + -1;
    if (iVar3 == 0) {
      return 0;
    }
  }
  if (((*(float *)(param_1 + 0xc) == (float)(&DAT_803a3414)[iVar2 * 4]) &&
      (*(float *)(param_1 + 0x10) == (float)(&DAT_803a3418)[iVar2 * 4])) &&
     (*(float *)(param_1 + 0x14) == (float)(&DAT_803a341c)[iVar2 * 4])) {
    return 0;
  }
  *(undefined4 *)(param_1 + 0xc) = (&DAT_803a3414)[iVar2 * 4];
  *(undefined4 *)(param_1 + 0x10) = (&DAT_803a3418)[iVar2 * 4];
  *(undefined4 *)(param_1 + 0x14) = (&DAT_803a341c)[iVar2 * 4];
  return 1;
}

