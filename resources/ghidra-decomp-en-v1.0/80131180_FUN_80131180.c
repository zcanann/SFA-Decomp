// Function: FUN_80131180
// Entry: 80131180
// Size: 108 bytes

void FUN_80131180(void)

{
  int iVar1;
  undefined2 *puVar2;
  
  puVar2 = &DAT_803a9458;
  for (iVar1 = 0; iVar1 < DAT_803dd911; iVar1 = iVar1 + 1) {
    if (*(int *)(puVar2 + 8) != 0) {
      FUN_80054308();
    }
    puVar2 = puVar2 + 0x1e;
  }
  DAT_803dd911 = 0;
  return;
}

