// Function: FUN_800e8384
// Entry: 800e8384
// Size: 104 bytes

undefined4 FUN_800e8384(int param_1)

{
  undefined1 *puVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = 0;
  puVar1 = &DAT_803a3f08;
  iVar3 = 0x3f;
  do {
    if (*(int *)(param_1 + 0x14) == *(int *)(puVar1 + 0x168)) {
      *(undefined4 *)(param_1 + 8) = (&DAT_803a4074)[iVar2 * 4];
      *(undefined4 *)(param_1 + 0xc) = (&DAT_803a4078)[iVar2 * 4];
      *(undefined4 *)(param_1 + 0x10) = (&DAT_803a407c)[iVar2 * 4];
      return 1;
    }
    puVar1 = puVar1 + 0x10;
    iVar2 = iVar2 + 1;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  return 0;
}

