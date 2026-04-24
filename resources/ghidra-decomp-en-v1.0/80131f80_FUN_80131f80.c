// Function: FUN_80131f80
// Entry: 80131f80
// Size: 96 bytes

void FUN_80131f80(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = 0;
  puVar2 = &DAT_803a9db8;
  do {
    FUN_80054308(*puVar2);
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 6);
  return;
}

