// Function: FUN_80131508
// Entry: 80131508
// Size: 108 bytes

void FUN_80131508(void)

{
  int iVar1;
  undefined2 *puVar2;
  
  puVar2 = &DAT_803aa0b8;
  for (iVar1 = 0; iVar1 < DAT_803de591; iVar1 = iVar1 + 1) {
    if (*(int *)(puVar2 + 8) != 0) {
      FUN_80054484();
    }
    puVar2 = puVar2 + 0x1e;
  }
  DAT_803de591 = 0;
  return;
}

